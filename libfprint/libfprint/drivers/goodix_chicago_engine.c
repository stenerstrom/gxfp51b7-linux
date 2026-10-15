/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Ordinary libfprint actions over the original Goodix Engine service. Matching,
 * enrollment policy and sealed-template authentication remain in the enclave.
 */
#define FP_COMPONENT "goodix_chicago_engine"
#include "goodix_chicago_engine.h"
#include <gio/gunixsocketaddress.h>
#include <string.h>

#define ENGINE_RPC_TIMEOUT_SECONDS 150
#define ENGINE_POLL_MS 100

typedef struct {
  guint operation;
  guint32 request_id;
  guint64 session_id;
  gchar *path;
  GBytes *payload;
  gint peer_pid, observed_pid;
  guint64 peer_started, observed_started;
} EngineRequest;

typedef struct {
  guint event;
  guint64 session_id;
  GxoeMetadata metadata;
  GBytes *blob;
} EngineResponse;

typedef struct _FpiDeviceGoodixChicagoEngine {
  FpDevice parent;
  gchar *socket_path;
  GCancellable *cancellable;
  guint32 request_id;
  guint64 session_id;
  gint peer_pid;
  guint64 peer_started;
  guint timer, completed, original_used, target, last_event;
  gboolean busy, ending, action_started, possible_session;
  gboolean verify_ready, verify_match;
  GError *finish_error, *cleanup_error, *verify_retry;
  FpPrint *finished_print;
  GBytes *verify_template;
#ifdef CHICAGO_ENGINE_TEST_ONLY
  GTaskThreadFunc test_worker;
  gpointer test_data;
  guint test_peer_uid;
#endif
} FpiDeviceGoodixChicagoEngine;

typedef FpDeviceClass FpiDeviceGoodixChicagoEngineClass;
GType fpi_device_goodix_chicago_engine_get_type (void);
G_DEFINE_TYPE (FpiDeviceGoodixChicagoEngine, fpi_device_goodix_chicago_engine, FP_TYPE_DEVICE);

static const FpIdEntry id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_PLATFORM, .platform_acpi_id = "GXFP51B7" },
  { .udev_types = 0 },
};

static void start_request (FpiDeviceGoodixChicagoEngine *self, guint operation);
static void finish_action (FpiDeviceGoodixChicagoEngine *self, GError *error, gboolean close_session);

static void
request_free (gpointer data)
{
  EngineRequest *request = data;
  g_clear_pointer (&request->payload, g_bytes_unref);
  g_free (request->path);
  g_free (request);
}

static void
response_free (gpointer data)
{
  EngineResponse *response = data;
  if (!response) return;
  g_clear_pointer (&response->blob, g_bytes_unref);
  g_free (response);
}

static guint32
read_u32 (const guint8 *data)
{
  guint32 value;
  memcpy (&value, data, sizeof (value));
  return GUINT32_FROM_LE (value);
}

static void
read_peer_identity (GCredentials *credentials, gint *pid, guint64 *started, GError **error)
{
  g_autofree gchar *path = NULL, *contents = NULL;
  g_auto(GStrv) fields = NULL;
  gchar *tail, *end;
  gsize length;
  *pid = g_credentials_get_unix_pid (credentials, error);
  if (*pid < 1)
    {
      if (!*error) g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid backend PID");
      return;
    }
  path = g_strdup_printf ("/proc/%d/stat", *pid);
  if (!g_file_get_contents (path, &contents, &length, error)) return;
  tail = g_strrstr (contents, ") ");
  if (!tail || length > 4096) goto invalid;
  fields = g_strsplit (tail + 2, " ", 23);
  if (g_strv_length (fields) < 20) goto invalid;
  *started = g_ascii_strtoull (fields[19], &end, 10);
  if (*started && end != fields[19] && !*end) return;
invalid:
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid backend process identity");
}

static gboolean
invalid_response (GError **error)
{
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid original Engine response");
  return FALSE;
}

/* Decode before allocation. The same parser is exercised by malformed-frame
 * tests, including lengths, session generation, operation and request replay. */
static gboolean
decode_header (const EngineRequest *request, const GxoeHeader *wire,
               guint32 *length, guint64 *session, guint *event, GError **error)
{
  gint32 status = (gint32) GUINT32_FROM_LE ((guint32) wire->status);
  *length = GUINT32_FROM_LE (wire->payload_length);
  *session = GUINT64_FROM_LE (wire->session_id);
  *event = GUINT32_FROM_LE (wire->event);
  if (memcmp (wire->magic, GXOE_RESPONSE_MAGIC, 4) ||
      GUINT16_FROM_LE (wire->version) != GXOE_VERSION ||
      GUINT16_FROM_LE (wire->operation) != request->operation ||
      GUINT32_FROM_LE (wire->request_id) != request->request_id ||
      *length > GXOE_PAYLOAD_MAX || status < 0 || status > 4095)
    return invalid_response (error);
  if (request->operation == GXOE_OPEN_SESSION)
    {
      if ((!status && !*session) || (status && *session)) return invalid_response (error);
    }
  else if (*session != request->session_id) return invalid_response (error);
  if (status)
    {
      if (*length || *event) return invalid_response (error);
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (status),
                   "Original Engine operation %u failed (status %d)", request->operation, status);
      return FALSE;
    }
  if (*length < sizeof (GxoeMetadata)) return invalid_response (error);
  if (request->operation == GXOE_STEP)
    {
      if (*event < GXOE_WAIT_FINGER || *event > GXOE_NO_MATCH) return invalid_response (error);
    }
  else if (*event != ((request->operation == GXOE_CLOSE_SESSION || request->operation == GXOE_END_ACTION)
                      ? GXOE_CLOSED : GXOE_READY))
    return invalid_response (error);
  return TRUE;
}

static gboolean
decode_metadata (guint operation, guint event, const guint8 *payload, gsize length,
                 GxoeMetadata *metadata, GError **error)
{
  guint32 *fields = (guint32 *) metadata;
  if (length < sizeof (*metadata)) return invalid_response (error);
  for (guint i = 0; i < sizeof (*metadata) / 4; i++) fields[i] = read_u32 (payload + i * 4);
  if (metadata->flags & ~(GXOE_ADAPTIVE_UPDATE_DISCARDED | GXOE_REQUIRES_EMPTY_START | GXOE_RETRY_SESSION_RETAINED))
    return invalid_response (error);
  if ((metadata->flags & GXOE_RETRY_SESSION_RETAINED) &&
      (operation != GXOE_END_ACTION || event != GXOE_CLOSED ||
       metadata->flags != GXOE_RETRY_SESSION_RETAINED || metadata->used || metadata->target ||
       metadata->progress || metadata->hint || metadata->quality || metadata->coverage || metadata->blob_length))
    return invalid_response (error);
  if (length != sizeof (*metadata) + (gsize) metadata->blob_length ||
      metadata->blob_length > GXOE_TEMPLATE_MAX)
    return invalid_response (error);
  if (event == GXOE_ENROLL_COMPLETE)
    {
      if (metadata->blob_length < GXOE_TEMPLATE_MIN) return invalid_response (error);
    }
  else if (metadata->blob_length) return invalid_response (error);
  if ((metadata->flags & GXOE_ADAPTIVE_UPDATE_DISCARDED) &&
      event != GXOE_MATCH && operation != GXOE_DESCRIBE)
    return invalid_response (error);
  if (operation == GXOE_DESCRIBE)
    {
      if (metadata->target != GXOE_TARGET_COUNT || metadata->quality != GXOE_PROFILE ||
          metadata->coverage != GXOE_TEMPLATE_MAX) return invalid_response (error);
    }
  /* The original engine can retain evidence beyond its initial target. Its
   * progress field is an opaque original numeric, not a proven percentage. */
  else if (metadata->target > GXOE_TARGET_COUNT || metadata->used > 512)
    return invalid_response (error);
  return TRUE;
}

static void
rpc_worker (GTask *task, gpointer object, gpointer task_data, GCancellable *cancellable)
{
  EngineRequest *request = task_data;
  g_autoptr(GSocketClient) client = g_socket_client_new ();
  g_autoptr(GSocketAddress) address = g_unix_socket_address_new (request->path);
  g_autoptr(GSocketConnection) connection = NULL;
  g_autoptr(GCredentials) credentials = NULL;
  g_autoptr(GError) error = NULL;
  guint8 *payload = NULL;
  EngineResponse *response = NULL;
  GxoeHeader out = { 0 }, in;
  guint32 length = 0;
  guint event = 0, expected_uid = 0;
  guint64 session = 0;
  gsize received, sent_length = 0;
  const guint8 *sent = request->payload ? g_bytes_get_data (request->payload, &sent_length) : NULL;
#ifdef CHICAGO_ENGINE_TEST_ONLY
  expected_uid = ((FpiDeviceGoodixChicagoEngine *) object)->test_peer_uid;
#endif
  if (sent_length > GXOE_TEMPLATE_MAX) { invalid_response (&error); goto fail; }
  memcpy (out.magic, GXOE_REQUEST_MAGIC, 4);
  out.version = GUINT16_TO_LE (GXOE_VERSION);
  out.operation = GUINT16_TO_LE (request->operation);
  out.payload_length = GUINT32_TO_LE (sent_length);
  out.request_id = GUINT32_TO_LE (request->request_id);
  out.session_id = GUINT64_TO_LE (request->session_id);
  g_socket_client_set_timeout (client, ENGINE_RPC_TIMEOUT_SECONDS);
  connection = g_socket_client_connect (client, G_SOCKET_CONNECTABLE (address), cancellable, &error);
  if (!connection) goto fail;
  credentials = g_socket_get_credentials (g_socket_connection_get_socket (connection), &error);
  if (!credentials) goto fail;
  if (g_credentials_get_unix_user (credentials, &error) != expected_uid)
    {
      if (!error) g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                                       "Original Engine backend is not a root peer");
      goto fail;
    }
  read_peer_identity (credentials, &request->observed_pid, &request->observed_started, &error);
  if (error) goto fail;
  if (request->peer_pid && (request->peer_pid != request->observed_pid ||
                            request->peer_started != request->observed_started))
    {
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                           "Original Engine backend restarted during the session");
      goto fail;
    }
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (connection));
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  if (!g_output_stream_write_all (output, &out, sizeof (out), NULL, cancellable, &error) ||
      (sent_length && !g_output_stream_write_all (output, sent, sent_length, NULL, cancellable, &error)) ||
      !g_input_stream_read_all (input, &in, sizeof (in), &received, cancellable, &error)) goto fail;
  if (received != sizeof (in)) { invalid_response (&error); goto fail; }
  if (!decode_header (request, &in, &length, &session, &event, &error)) goto fail;
  payload = g_malloc (length);
  if (!g_input_stream_read_all (input, payload, length, &received, cancellable, &error)) goto fail;
  if (received != length) { invalid_response (&error); goto fail; }
  response = g_new0 (EngineResponse, 1);
  response->event = event;
  response->session_id = session;
  if (!decode_metadata (request->operation, event, payload, length, &response->metadata, &error)) goto fail;
  if (response->metadata.blob_length)
    response->blob = chicago_engine_bytes_new (payload + sizeof (GxoeMetadata), response->metadata.blob_length);
  chicago_engine_erase (payload, length);
  g_free (payload);
  if (g_cancellable_set_error_if_cancelled (cancellable, &error)) goto cancelled;
  g_task_return_pointer (task, response, response_free);
  return;
fail:
  if (payload) { chicago_engine_erase (payload, length); g_free (payload); }
cancelled:
  response_free (response);
  g_task_return_error (task, g_steal_pointer (&error));
}

static void
clear_poll (FpiDeviceGoodixChicagoEngine *self)
{
  if (self->timer) { g_source_remove (self->timer); self->timer = 0; }
}

static void
add_finish_error (FpiDeviceGoodixChicagoEngine *self, GError *error)
{
  if (!error) return;
  if (!self->finish_error) self->finish_error = error;
  else
    {
      GError *combined = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
          "%s; cleanup: %s", self->finish_error->message, error->message);
      g_clear_error (&self->finish_error);
      g_error_free (error);
      self->finish_error = combined;
    }
}

static void
complete_action (FpiDeviceGoodixChicagoEngine *self)
{
  FpDevice *device = FP_DEVICE (self);
  FpiDeviceAction action = fpi_device_get_current_action (device);
  GError *error = g_steal_pointer (&self->finish_error);
  FpPrint *print = g_steal_pointer (&self->finished_print);
  self->ending = self->action_started = FALSE;
  clear_poll (self);
  g_clear_pointer (&self->verify_template, g_bytes_unref);
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (!error && fpi_device_action_is_cancelled (device))
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled");
  if (error) g_clear_object (&print);
  if (action == FPI_DEVICE_ACTION_ENROLL)
    fpi_device_enroll_complete (device, print, error);
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    {
      g_clear_object (&print);
      if (!error && self->verify_retry)
        fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL, g_steal_pointer (&self->verify_retry));
      else if (!error && self->verify_ready)
        fpi_device_verify_report (device, self->verify_match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, NULL, NULL);
      g_clear_error (&self->verify_retry);
      self->verify_ready = FALSE;
      fpi_device_verify_complete (device, error);
    }
  else if (action == FPI_DEVICE_ACTION_OPEN) fpi_device_open_complete (device, error);
  else if (action == FPI_DEVICE_ACTION_CLOSE) fpi_device_close_complete (device, error);
  else { g_clear_object (&print); g_clear_error (&error); }
}

static void
finish_action (FpiDeviceGoodixChicagoEngine *self, GError *error, gboolean close_session)
{
  if (self->ending) { g_clear_error (&error); return; }
  self->ending = TRUE;
  clear_poll (self);
  add_finish_error (self, error);
  if (self->possible_session && (close_session || self->action_started))
    start_request (self, close_session ? GXOE_CLOSE_SESSION : GXOE_END_ACTION);
  else complete_action (self);
}

static gboolean
poll_step (gpointer data)
{
  FpiDeviceGoodixChicagoEngine *self = data;
  self->timer = 0;
  if (fpi_device_action_is_cancelled (FP_DEVICE (self)))
    finish_action (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled"), TRUE);
  else start_request (self, GXOE_STEP);
  return G_SOURCE_REMOVE;
}

static void
schedule_step (FpiDeviceGoodixChicagoEngine *self)
{
  if (!self->ending && !self->timer)
    self->timer = g_timeout_add (ENGINE_POLL_MS, poll_step, self);
}

static void
handle_step (FpiDeviceGoodixChicagoEngine *self, EngineResponse *response)
{
  FpDevice *device = FP_DEVICE (self);
  gboolean enrolling = fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_ENROLL;
  GxoeMetadata *meta = &response->metadata;
  g_autoptr(GError) error = NULL;
  switch (response->event)
    {
    case GXOE_WAIT_FINGER:
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
      break;
    case GXOE_WAIT_REMOVE:
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
      if (enrolling && self->last_event != GXOE_WAIT_REMOVE)
        fpi_device_enroll_progress (device, self->completed, NULL,
                                   fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
      break;
    case GXOE_RETRY:
      if (enrolling)
        fpi_device_enroll_progress (device, self->completed, NULL,
                                   fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      else
        {
          self->verify_retry = fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER);
          finish_action (self, NULL, FALSE);
          return;
        }
      break;
    case GXOE_ENROLL_ACCEPTED:
      if (!enrolling || !meta->target || meta->used <= self->original_used)
        goto invalid;
      self->target = meta->target;
      fpi_device_set_nr_enroll_stages (device, self->target);
      self->original_used = meta->used;
      self->completed = MIN (meta->used, self->target - 1);
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
      fpi_device_enroll_progress (device, self->completed, NULL, NULL);
      break;
    case GXOE_ENROLL_COMPLETE:
      if (!enrolling || !response->blob || !meta->used || meta->used < self->original_used) goto invalid;
      FpPrint *print;
      fpi_device_get_enroll_data (device, &print);
      if (!chicago_engine_set_print (print, response->blob, &error))
        { finish_action (self, g_steal_pointer (&error), TRUE); return; }
      self->finished_print = g_object_ref (print);
      /* Original finalization can finish before its initial target. Do not add
       * synthetic acquisitions or retain the SIFT driver's rehearsal policy. */
      self->original_used = meta->used;
      guint final_stages = MIN (meta->used, self->target);
      fpi_device_set_nr_enroll_stages (device, final_stages);
      if (final_stages > self->completed)
        fpi_device_enroll_progress (device, final_stages, NULL, NULL);
      self->completed = final_stages;
      finish_action (self, NULL, FALSE);
      return;
    case GXOE_MATCH:
    case GXOE_NO_MATCH:
      if (enrolling) goto invalid;
      self->verify_ready = TRUE;
      self->verify_match = response->event == GXOE_MATCH;
      /* A discarded original adaptive update remains a successful match. No
       * unequal scanned print is returned as a speculative storage update. */
      finish_action (self, NULL, FALSE);
      return;
    default:
      goto invalid;
    }
  self->last_event = response->event;
  schedule_step (self);
  return;
invalid:
  invalid_response (&error);
  finish_action (self, g_steal_pointer (&error), TRUE);
}

static void
request_done (GObject *object, GAsyncResult *result, gpointer user_data)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) object;
  FpDevice *device = FP_DEVICE (self);
  GTask *task = G_TASK (result);
  EngineRequest *request = g_task_get_task_data (task);
  g_autoptr(GError) error = NULL;
  EngineResponse *response = g_task_propagate_pointer (task, &error);
  self->busy = FALSE;
  /* Bind even a cancelled/failed OPEN to the authenticated peer that received
   * it, so a fresh uncancellable CLOSE cannot affect a replacement service. */
  if (request->operation != GXOE_DESCRIBE && request->observed_pid && !self->peer_pid)
    { self->peer_pid = request->observed_pid; self->peer_started = request->observed_started; }
  if (request->operation == GXOE_DESCRIBE)
    {
      fpi_device_probe_complete (device, "GXFP51B7:00", "Goodix ChicagoHS (original Engine)",
                                 g_steal_pointer (&error));
      goto out;
    }
  if (request->operation == GXOE_CLOSE_SESSION || request->operation == GXOE_END_ACTION)
    {
      if (response && (response->metadata.flags & GXOE_RETRY_SESSION_RETAINED))
        {
          if (request->operation != GXOE_END_ACTION || !self->verify_retry ||
              fpi_device_get_current_action (device) != FPI_DEVICE_ACTION_VERIFY)
            { invalid_response (&error); add_finish_error (self, g_steal_pointer (&error)); }
          if (fpi_device_action_is_cancelled (device))
            add_finish_error (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled"));
          if (self->finish_error)
            { start_request (self, GXOE_CLOSE_SESSION); goto out; }
        }
      if (error)
        {
          add_finish_error (self, g_steal_pointer (&error));
          if (request->operation == GXOE_END_ACTION)
            { start_request (self, GXOE_CLOSE_SESSION); goto out; }
          g_clear_error (&self->cleanup_error);
          self->cleanup_error = g_error_copy (self->finish_error);
        }
      if (request->operation == GXOE_CLOSE_SESSION)
        {
          self->session_id = 0;
          self->possible_session = FALSE;
          if (!self->cleanup_error) { self->peer_pid = 0; self->peer_started = 0; }
        }
      complete_action (self);
      goto out;
    }
  if (response && request->operation == GXOE_OPEN_SESSION) self->session_id = response->session_id;
  if (!error && fpi_device_action_is_cancelled (device))
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled");
  if (error) { finish_action (self, g_steal_pointer (&error), TRUE); goto out; }
  if (request->operation == GXOE_OPEN_SESSION)
    {
      if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_OPEN)
        fpi_device_open_complete (device, NULL);
      else start_request (self, self->verify_template ? GXOE_BEGIN_VERIFY : GXOE_BEGIN_ENROLL);
    }
  else if (request->operation == GXOE_BEGIN_ENROLL || request->operation == GXOE_BEGIN_VERIFY)
    {
      self->action_started = TRUE;
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
      schedule_step (self);
    }
  else handle_step (self, response);
out:
  response_free (response);
}

static void
start_request (FpiDeviceGoodixChicagoEngine *self, guint operation)
{
  g_autoptr(GTask) task = NULL;
  EngineRequest *request = g_new0 (EngineRequest, 1);
  gboolean cleanup = operation == GXOE_END_ACTION || operation == GXOE_CLOSE_SESSION;
  g_assert (!self->busy);
  request->operation = operation;
  request->request_id = ++self->request_id;
  request->session_id = operation == GXOE_DESCRIBE || operation == GXOE_OPEN_SESSION ? 0 : self->session_id;
  request->path = g_strdup (self->socket_path);
  request->peer_pid = self->peer_pid;
  request->peer_started = self->peer_started;
  if (operation == GXOE_BEGIN_VERIFY) request->payload = g_bytes_ref (self->verify_template);
  if (operation == GXOE_OPEN_SESSION) self->possible_session = TRUE;
  self->busy = TRUE;
  task = g_task_new (self, cleanup ? NULL : self->cancellable, request_done, NULL);
  g_task_set_check_cancellable (task, FALSE);
  g_task_set_task_data (task, request, request_free);
#ifdef CHICAGO_ENGINE_TEST_ONLY
  g_task_run_in_thread (task, self->test_worker ? self->test_worker : rpc_worker);
#else
  g_task_run_in_thread (task, rpc_worker);
#endif
}

static void
engine_probe (FpDevice *device)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  const gchar *path = fpi_device_get_udev_data (device, FPI_DEVICE_UDEV_SUBTYPE_PLATFORM);
  if (!path || !g_str_has_suffix (path, "/GXFP51B7:00"))
    { fpi_device_probe_complete (device, NULL, NULL, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED)); return; }
  self->socket_path = g_strdup (GXOE_SOCKET_PATH);
  self->cancellable = g_cancellable_new ();
  start_request (self, GXOE_DESCRIBE);
}

static void
engine_open (FpDevice *device)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  if (self->cleanup_error)
    { fpi_device_open_complete (device, g_steal_pointer (&self->cleanup_error)); return; }
  if (!self->possible_session) { self->peer_pid = 0; self->peer_started = 0; }
  self->ending = FALSE;
  g_cancellable_reset (self->cancellable);
  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  g_message ("Original Engine startup requires an empty fingerprint reader");
  start_request (self, GXOE_OPEN_SESSION);
}

static void
engine_close (FpDevice *device)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  self->ending = FALSE;
  finish_action (self, g_steal_pointer (&self->cleanup_error), TRUE);
}

static void
engine_begin (FpDevice *device)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  g_autoptr(GError) error = NULL;
  self->ending = self->verify_ready = FALSE;
  self->completed = self->original_used = self->last_event = 0;
  self->target = GXOE_TARGET_COUNT;
  g_clear_error (&self->verify_retry);
  g_clear_pointer (&self->verify_template, g_bytes_unref);
  g_cancellable_reset (self->cancellable);
  if (self->cleanup_error)
    { finish_action (self, g_error_copy (self->cleanup_error), TRUE); return; }
  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *print;
      fpi_device_get_verify_data (device, &print);
      self->verify_template = chicago_engine_get_print (print, &error);
      if (!self->verify_template) { finish_action (self, g_steal_pointer (&error), FALSE); return; }
    }
  else fpi_device_set_nr_enroll_stages (device, self->target);
  if (!self->session_id) start_request (self, GXOE_OPEN_SESSION);
  else start_request (self, self->verify_template ? GXOE_BEGIN_VERIFY : GXOE_BEGIN_ENROLL);
}

static void
engine_cancel (FpDevice *device)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  if (self->ending) return;
  clear_poll (self);
  g_cancellable_cancel (self->cancellable);
  if (!self->busy)
    finish_action (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled"), TRUE);
}

static void
engine_finalize (GObject *object)
{
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) object;
  clear_poll (self);
  g_clear_error (&self->finish_error);
  g_clear_error (&self->cleanup_error);
  g_clear_error (&self->verify_retry);
  g_clear_object (&self->finished_print);
  g_clear_pointer (&self->verify_template, g_bytes_unref);
  g_clear_object (&self->cancellable);
  g_clear_pointer (&self->socket_path, g_free);
  G_OBJECT_CLASS (fpi_device_goodix_chicago_engine_parent_class)->finalize (object);
}

static void
fpi_device_goodix_chicago_engine_init (FpiDeviceGoodixChicagoEngine *self)
{
}

static void
fpi_device_goodix_chicago_engine_class_init (FpiDeviceGoodixChicagoEngineClass *class)
{
  G_OBJECT_CLASS (class)->finalize = engine_finalize;
  class->id = "goodix_chicago_engine";
  class->full_name = "Goodix ChicagoHS (original Engine)";
  class->type = FP_DEVICE_TYPE_UDEV;
  class->id_table = id_table;
  class->scan_type = FP_SCAN_TYPE_PRESS;
  class->nr_enroll_stages = GXOE_TARGET_COUNT;
  class->temp_hot_seconds = -1;
  class->probe = engine_probe;
  class->open = engine_open;
  class->close = engine_close;
  class->enroll = engine_begin;
  class->verify = engine_begin;
  class->cancel = engine_cancel;
  fpi_device_class_auto_initialize_features (class);
}
