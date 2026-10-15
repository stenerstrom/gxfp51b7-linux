/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Synthetic public API, framing and opaque-template tests. No sensor data.
 */
#define CHICAGO_ENGINE_TEST_ONLY
#include "../libfprint/drivers/goodix_chicago_engine.c"
#include <unistd.h>
#include <glib/gstdio.h>

typedef struct {
  guint event, used, flags;
} Step;

typedef struct {
  Step steps[24];
  guint count, position, opens, begins, ends, closes, accepted, retries, action;
  gboolean fail_end, fail_close, cancel_open, cancel_step, cancel_end, retain_retry;
  GCancellable *cancel;
} Fixture;

static GBytes *
synthetic_blob (void)
{
  guint8 bytes[GXOE_TEMPLATE_MIN + 32] = { 0 };
  bytes[0] = 0x71;
  return chicago_engine_bytes_new (bytes, sizeof (bytes));
}

static void
fake_rpc (GTask *task, gpointer object, gpointer data, GCancellable *cancellable)
{
  FpiDeviceGoodixChicagoEngine *self = object;
  Fixture *fixture = self->test_data;
  EngineRequest *request = data;
  EngineResponse *response = g_new0 (EngineResponse, 1);
  request->observed_pid = 4242;
  request->observed_started = 5678;
  response->session_id = request->session_id;
  response->event = GXOE_READY;
  response->metadata.target = GXOE_TARGET_COUNT;
  if (request->operation == GXOE_OPEN_SESSION)
    {
      fixture->opens++;
      response->session_id = 99;
      if (fixture->cancel_open)
        {
          g_cancellable_cancel (fixture->cancel);
          response_free (response);
          g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Synthetic pending open cancelled");
          return;
        }
    }
  else if (request->operation == GXOE_BEGIN_ENROLL || request->operation == GXOE_BEGIN_VERIFY)
    {
      fixture->begins++;
      fixture->action = request->operation;
      if (request->operation == GXOE_BEGIN_VERIFY)
        {
          g_autoptr(GBytes) expected = synthetic_blob ();
          g_assert_true (g_bytes_equal (expected, request->payload));
        }
    }
  else if (request->operation == GXOE_STEP)
    {
      g_assert_cmpuint (fixture->position, <, fixture->count);
      Step step = fixture->steps[fixture->position++];
      response->event = step.event;
      response->metadata.used = step.used;
      response->metadata.flags = step.flags;
      if (step.event == GXOE_ENROLL_COMPLETE)
        response->blob = synthetic_blob ();
      if (fixture->cancel_step) g_cancellable_cancel (fixture->cancel);
    }
  else if (request->operation == GXOE_END_ACTION)
    {
      g_assert_null (cancellable);
      fixture->ends++;
      response->event = GXOE_CLOSED;
      response->metadata = (GxoeMetadata){ 0 };
      if (fixture->retain_retry && fixture->action == GXOE_BEGIN_VERIFY && fixture->position &&
          fixture->steps[fixture->position - 1].event == GXOE_RETRY)
        response->metadata.flags = GXOE_RETRY_SESSION_RETAINED;
      if (fixture->cancel_end) g_cancellable_cancel (fixture->cancel);
      if (fixture->fail_end)
        {
          response_free (response);
          g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_FAILED, "Synthetic END failure");
          return;
        }
    }
  else if (request->operation == GXOE_CLOSE_SESSION)
    {
      g_assert_null (cancellable);
      fixture->closes++;
      response->event = GXOE_CLOSED;
      if (fixture->fail_close)
        {
          response_free (response);
          g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_FAILED, "Synthetic CLOSE failure");
          return;
        }
    }
  g_task_return_pointer (task, response, response_free);
}

typedef struct { gboolean done; GError *error; } Init;
static void
init_done (GObject *object, GAsyncResult *result, gpointer data)
{
  Init *init = data;
  g_async_initable_init_finish (G_ASYNC_INITABLE (object), result, &init->error);
  init->done = TRUE;
}

static FpDevice *
new_device (Fixture *fixture, gboolean open)
{
  FpDevice *device = g_object_new (fpi_device_goodix_chicago_engine_get_type (),
                                  "fpi-udev-data-platform", "/synthetic/GXFP51B7:00", NULL);
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  Init init = { 0 };
  self->test_worker = fake_rpc;
  self->test_data = fixture;
  g_async_initable_init_async (G_ASYNC_INITABLE (device), G_PRIORITY_DEFAULT, NULL, init_done, &init);
  while (!init.done) g_main_context_iteration (NULL, TRUE);
  g_assert_no_error (init.error);
  if (open)
    {
      g_autoptr(GError) error = NULL;
      g_assert_true (fp_device_open_sync (device, NULL, &error));
      g_assert_no_error (error);
    }
  return device;
}

static void
close_device (FpDevice *device)
{
  g_autoptr(GError) error = NULL;
  if (fp_device_is_open (device)) g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_assert_no_error (error);
}

static FpPrint *
stored_print (FpDevice *device)
{
  FpPrint *print = g_object_ref_sink (fp_print_new (device));
  g_autoptr(GBytes) blob = synthetic_blob ();
  g_autoptr(GError) error = NULL;
  g_assert_true (chicago_engine_set_print (print, blob, &error));
  g_assert_no_error (error);
  return print;
}

static void
progress (FpDevice *device, gint completed, FpPrint *print, gpointer data, GError *error)
{
  Fixture *fixture = data;
  if (error)
    {
      g_assert_cmpuint (error->domain, ==, FP_DEVICE_RETRY);
      fixture->retries++;
    }
  else
    {
      g_assert_cmpuint (completed, >, fixture->accepted);
      fixture->accepted = completed;
    }
}

static void
test_enrollment (gconstpointer data)
{
  gboolean beyond_target = GPOINTER_TO_INT (data);
  Fixture fixture = { .steps = {{GXOE_WAIT_FINGER}, {GXOE_RETRY}, {GXOE_ENROLL_ACCEPTED, 1},
                                {GXOE_WAIT_REMOVE}, {GXOE_WAIT_REMOVE}, {GXOE_WAIT_FINGER},
                                {GXOE_ENROLL_ACCEPTED, 11}, {GXOE_ENROLL_COMPLETE, 12}}, .count = 8 };
  if (beyond_target)
    { fixture.steps[6].used = 21; fixture.steps[7].used = 24; }
  g_autoptr(FpDevice) device = new_device (&fixture, TRUE);
  g_autoptr(FpPrint) empty = g_object_ref_sink (fp_print_new (device));
  g_autoptr(GError) error = NULL;
  g_autoptr(FpPrint) print = fp_device_enroll_sync (device, empty, NULL, progress, &fixture, &error);
  g_assert_no_error (error);
  g_assert_nonnull (print);
  g_assert_false (fp_print_get_device_stored (print));
  g_assert_cmpuint (fixture.accepted, ==, beyond_target ? 20 : 12);
  g_assert_cmpuint (((FpiDeviceGoodixChicagoEngine *) device)->original_used, ==, beyond_target ? 24 : 12);
  g_assert_cmpuint (fixture.retries, ==, 2);
  g_assert_cmpuint (fixture.opens, ==, 1);
  g_assert_cmpuint (fixture.begins, ==, 1);
  g_assert_cmpuint (fixture.ends, ==, 1);
  g_autoptr(GBytes) actual = chicago_engine_get_print (print, &error);
  g_autoptr(GBytes) expected = synthetic_blob ();
  g_assert_no_error (error);
  g_assert_true (g_bytes_equal (actual, expected));
  close_device (device);
}

static void
test_verify_results (void)
{
  Fixture fixture = { .steps = {{GXOE_WAIT_REMOVE}, {GXOE_WAIT_FINGER}, {GXOE_RETRY},
                                {GXOE_MATCH, 0, GXOE_ADAPTIVE_UPDATE_DISCARDED}, {GXOE_NO_MATCH}},
                      .count = 5, .retain_retry = TRUE };
  g_autoptr(FpDevice) device = new_device (&fixture, TRUE);
  g_autoptr(FpPrint) print = stored_print (device);
  g_autoptr(GBytes) before = chicago_engine_get_print (print, NULL);
  g_autoptr(GError) error = NULL;
  gboolean match = FALSE;
  g_assert_false (fp_device_verify_sync (device, print, NULL, NULL, NULL, &match, NULL, &error));
  g_assert_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_REMOVE_FINGER);
  g_clear_error (&error);
  g_assert_true (fp_device_verify_sync (device, print, NULL, NULL, NULL, &match, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (match);
  g_autoptr(GBytes) after = chicago_engine_get_print (print, NULL);
  g_assert_true (g_bytes_equal (before, after));
  g_assert_true (fp_device_verify_sync (device, print, NULL, NULL, NULL, &match, NULL, &error));
  g_assert_no_error (error);
  g_assert_false (match);
  g_assert_cmpuint (fixture.opens, ==, 1);
  g_assert_cmpuint (fixture.begins, ==, 3);
  g_assert_cmpuint (fixture.ends, ==, 3);
  close_device (device);
}

static void
test_cancel_retained_retry (void)
{
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  Fixture fixture = { .steps = {{GXOE_RETRY}}, .count = 1, .cancel = cancel,
                      .cancel_end = TRUE, .retain_retry = TRUE };
  g_autoptr(FpDevice) device = new_device (&fixture, TRUE);
  g_autoptr(FpPrint) print = stored_print (device);
  g_autoptr(GError) error = NULL;
  gboolean match = FALSE;
  g_assert_false (fp_device_verify_sync (device, print, cancel, NULL, NULL, &match, NULL, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_false (match);
  g_assert_cmpuint (fixture.ends, ==, 1);
  g_assert_cmpuint (fixture.closes, ==, 1);
  g_assert_cmpuint (((FpiDeviceGoodixChicagoEngine *) device)->session_id, ==, 0);
  close_device (device);
}

static void
test_cancel (gconstpointer data)
{
  gboolean during_open = GPOINTER_TO_INT (data);
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  Fixture fixture = { .steps = {{GXOE_MATCH}}, .count = 1, .cancel = cancel,
                      .cancel_open = during_open, .cancel_step = !during_open };
  g_autoptr(FpDevice) device = new_device (&fixture, !during_open);
  g_autoptr(GError) error = NULL;
  gboolean match;
  if (during_open)
    g_assert_false (fp_device_open_sync (device, cancel, &error));
  else
    {
      g_autoptr(FpPrint) print = stored_print (device);
      g_assert_false (fp_device_verify_sync (device, print, cancel, NULL, NULL, &match, NULL, &error));
    }
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_cmpuint (fixture.closes, ==, 1);
  g_assert_cmpuint (fixture.ends, ==, 0);
  g_assert_cmpuint (((FpiDeviceGoodixChicagoEngine *) device)->session_id, ==, 0);
  close_device (device);
}

static void
test_cleanup_failure (void)
{
  Fixture fixture = { .steps = {{GXOE_MATCH}}, .count = 1, .fail_end = TRUE };
  g_autoptr(FpDevice) device = new_device (&fixture, TRUE);
  g_autoptr(FpPrint) print = stored_print (device);
  g_autoptr(GError) error = NULL;
  gboolean match = FALSE;
  g_assert_false (fp_device_verify_sync (device, print, NULL, NULL, NULL, &match, NULL, &error));
  g_assert_nonnull (error);
  g_assert_false (match);
  g_assert_cmpuint (fixture.ends, ==, 1);
  g_assert_cmpuint (fixture.closes, ==, 1);
  close_device (device);
}

static void
test_codec (void)
{
  Fixture fixture = { 0 };
  g_autoptr(FpDevice) device = new_device (&fixture, FALSE);
  g_autoptr(FpPrint) print = stored_print (device);
  g_autoptr(GError) error = NULL;
  guint8 *serialized = NULL;
  gsize size;
  g_assert_true (fp_print_serialize (print, &serialized, &size, &error));
  g_assert_no_error (error);
  g_autoptr(FpPrint) restored = fp_print_deserialize (serialized, size, &error);
  chicago_engine_erase (serialized, size);
  g_free (serialized);
  g_assert_no_error (error);
  g_autoptr(GBytes) blob = chicago_engine_get_print (restored, &error);
  g_assert_no_error (error);
  g_autoptr(GBytes) expected = synthetic_blob ();
  g_assert_true (g_bytes_equal (blob, expected));
  for (guint i = 0; i < 6; i++)
    {
      guint8 tiny[GXOE_TEMPLATE_MIN] = { 0 };
      gsize length = i == 4 ? sizeof (tiny) - 1 : sizeof (tiny);
      GVariant *array = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, tiny, length, 1);
      g_autoptr(GVariant) bad = g_variant_ref_sink (g_variant_new ("(susu@ay)",
          i == 0 ? "goodix-chicago-full-sift" : GXOE_ENROLL_MARKER,
          i == 1 ? 2u : GXOE_TEMPLATE_SCHEMA, i == 2 ? "other-engine" : GXOE_ENGINE_SHA256,
          i == 3 ? 13u : GXOE_PROFILE, array));
      g_object_set (restored, "fpi-data", bad, NULL);
      fpi_print_set_device_stored (restored, i == 5);
      g_assert_null (chicago_engine_get_print (restored, &error));
      g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
      g_clear_error (&error);
    }
  guint8 *large = g_malloc0 (GXOE_TEMPLATE_MAX + 1);
  g_autoptr(GBytes) oversize = g_bytes_new_take (large, GXOE_TEMPLATE_MAX + 1);
  g_assert_false (chicago_engine_set_print (print, oversize, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
}

static void
test_protocol (void)
{
  EngineRequest request = { .operation = GXOE_STEP, .request_id = 7, .session_id = 99 };
  GxoeHeader wire = { .magic = GXOE_RESPONSE_MAGIC, .version = GUINT16_TO_LE (GXOE_VERSION),
                     .operation = GUINT16_TO_LE (GXOE_STEP), .payload_length = GUINT32_TO_LE (32),
                     .request_id = GUINT32_TO_LE (7), .session_id = GUINT64_TO_LE (99),
                     .event = GUINT32_TO_LE (GXOE_MATCH) };
  GxoeMetadata metadata;
  guint8 payload[32] = { 0 };
  guint32 length;
  guint event;
  guint64 session;
  g_autoptr(GError) error = NULL;
  g_assert_true (decode_header (&request, &wire, &length, &session, &event, &error));
  g_assert_true (decode_metadata (GXOE_STEP, GXOE_MATCH, payload, sizeof (payload), &metadata, &error));
  /* Original counters are not an extra host acceptance rule. A raw progress
   * value above 100 and more evidence than target20 remain legitimate. */
  guint32 count = GUINT32_TO_LE (512), raw_progress = GUINT32_TO_LE (0xffffffff);
  memcpy (payload, &count, 4);
  memcpy (payload + 8, &raw_progress, 4);
  g_assert_true (decode_metadata (GXOE_STEP, GXOE_ENROLL_ACCEPTED, payload, sizeof (payload), &metadata, &error));
  count = GUINT32_TO_LE (513);
  memcpy (payload, &count, 4);
  g_assert_false (decode_metadata (GXOE_STEP, GXOE_ENROLL_ACCEPTED, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  memset (payload, 0, sizeof (payload));
  payload[24] = GXOE_RETRY_SESSION_RETAINED;
  g_assert_true (decode_metadata (GXOE_END_ACTION, GXOE_CLOSED, payload, sizeof (payload), &metadata, &error));
  g_assert_false (decode_metadata (GXOE_CLOSE_SESSION, GXOE_CLOSED, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  g_assert_false (decode_metadata (GXOE_STEP, GXOE_MATCH, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  payload[0] = 1;
  g_assert_false (decode_metadata (GXOE_END_ACTION, GXOE_CLOSED, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  memset (payload, 0, sizeof (payload));
  for (guint i = 0; i < 8; i++)
    {
      GxoeHeader bad = wire;
      switch (i)
        {
        case 0: bad.magic[0] = 'X'; break;
        case 1: bad.version = GUINT16_TO_LE (1); break;
        case 2: bad.operation = GUINT16_TO_LE (GXOE_BEGIN_VERIFY); break;
        case 3: bad.request_id = GUINT32_TO_LE (6); break;
        case 4: bad.session_id = GUINT64_TO_LE (100); break;
        case 5: bad.payload_length = GUINT32_TO_LE (GXOE_PAYLOAD_MAX + 1); break;
        case 6: bad.status = GUINT32_TO_LE (4096); break;
        case 7: bad.event = GUINT32_TO_LE (GXOE_ENROLL_COMPLETE); bad.payload_length = 0; break;
        }
      g_assert_false (decode_header (&request, &bad, &length, &session, &event, &error));
      g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
      g_clear_error (&error);
    }
  payload[28] = 1;
  g_assert_false (decode_metadata (GXOE_STEP, GXOE_MATCH, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  payload[28] = 0;
  payload[24] = GXOE_ADAPTIVE_UPDATE_DISCARDED;
  g_assert_false (decode_metadata (GXOE_STEP, GXOE_NO_MATCH, payload, sizeof (payload), &metadata, &error));
  g_clear_error (&error);
  g_assert_false (decode_metadata (GXOE_STEP, GXOE_MATCH, payload, 31, &metadata, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
}

/* Exercise the actual GIO transport, SO_PEERCRED binding and EOF paths. Only
 * synthetic metadata travels over a private temporary Unix socket. */
typedef struct {
  GSocketListener *listener;
  GCancellable *cancel;
  guint mode;
  gsize request_bytes;
} WireServer;

static gpointer
wire_server (gpointer data)
{
  WireServer *server = data;
  g_autoptr(GError) error = NULL;
  g_autoptr(GSocketConnection) connection =
      g_socket_listener_accept (server->listener, NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (connection);
  g_socket_set_timeout (g_socket_connection_get_socket (connection), 2);
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (connection));
  GxoeHeader request;
  g_assert_true (g_input_stream_read_all (input, &request, sizeof (request),
                                         &server->request_bytes, NULL, &error));
  g_assert_no_error (error);
  if (!server->request_bytes) return NULL;
  g_assert_cmpuint (server->request_bytes, ==, sizeof (request));
  g_assert_cmpmem (request.magic, 4, GXOE_REQUEST_MAGIC, 4);
  g_assert_cmpuint (GUINT16_FROM_LE (request.operation), ==, GXOE_DESCRIBE);
  if (server->mode == 5)
    {
      g_cancellable_cancel (server->cancel);
      return NULL;
    }
  GxoeHeader reply = request;
  memcpy (reply.magic, GXOE_RESPONSE_MAGIC, 4);
  reply.event = GUINT32_TO_LE (GXOE_READY);
  reply.payload_length = GUINT32_TO_LE (sizeof (GxoeMetadata));
  GxoeMetadata metadata = { .target = GUINT32_TO_LE (GXOE_TARGET_COUNT),
                           .quality = GUINT32_TO_LE (GXOE_PROFILE),
                           .coverage = GUINT32_TO_LE (GXOE_TEMPLATE_MAX),
                           .flags = GUINT32_TO_LE (GXOE_REQUIRES_EMPTY_START) };
  if (server->mode == 6)
    { reply.status = GUINT32_TO_LE (EBUSY); reply.event = reply.payload_length = 0; }
  g_assert_true (g_output_stream_write_all (output, &reply, server->mode == 1 ? 10 : sizeof (reply),
                                           NULL, NULL, &error));
  g_assert_no_error (error);
  if (server->mode != 1 && server->mode != 6)
    {
      g_assert_true (g_output_stream_write_all (output, &metadata,
                                               server->mode == 2 ? 8 : sizeof (metadata),
                                               NULL, NULL, &error));
      g_assert_no_error (error);
    }
  return NULL;
}

typedef struct { gboolean done; EngineResponse *response; GError *error; } WireResult;
static void
wire_done (GObject *object, GAsyncResult *result, gpointer data)
{
  WireResult *wire = data;
  wire->response = g_task_propagate_pointer (G_TASK (result), &wire->error);
  wire->done = TRUE;
}

static void
test_transport (gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  Fixture fixture = { 0 };
  g_autoptr(FpDevice) device = new_device (&fixture, FALSE);
  FpiDeviceGoodixChicagoEngine *self = (FpiDeviceGoodixChicagoEngine *) device;
  g_autoptr(GError) error = NULL;
  g_autofree gchar *directory = g_dir_make_tmp ("goodix-engine-test-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (directory, "reader.sock", NULL);
  g_autoptr(GSocketAddress) address = g_unix_socket_address_new (path);
  g_autoptr(GSocketListener) listener = g_socket_listener_new ();
  g_assert_true (g_socket_listener_add_address (listener, address, G_SOCKET_TYPE_STREAM,
                                               G_SOCKET_PROTOCOL_DEFAULT, NULL, NULL, &error));
  g_assert_no_error (error);
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  WireServer server = { .listener = listener, .cancel = cancel, .mode = mode };
  GThread *thread = g_thread_new ("synthetic-engine", wire_server, &server);
  self->test_peer_uid = getuid () + (mode == 3);
  EngineRequest *request = g_new0 (EngineRequest, 1);
  request->operation = GXOE_DESCRIBE;
  request->request_id = 17;
  request->path = g_strdup (path);
  if (mode == 4) request->peer_pid = getpid () + 1;
  WireResult result = { 0 };
  g_autoptr(GTask) task = g_task_new (self, cancel, wire_done, &result);
  g_task_set_check_cancellable (task, FALSE);
  g_task_set_task_data (task, request, request_free);
  g_task_run_in_thread (task, rpc_worker);
  while (!result.done) g_main_context_iteration (NULL, TRUE);
  g_thread_join (thread);
  if (mode == 0)
    {
      g_assert_no_error (result.error);
      g_assert_nonnull (result.response);
      g_assert_cmpuint (result.response->event, ==, GXOE_READY);
      g_assert_cmpint (request->observed_pid, ==, getpid ());
      g_assert_cmpuint (request->observed_started, >, 0);
    }
  else
    {
      gint code = mode == 3 ? G_IO_ERROR_PERMISSION_DENIED :
                  mode == 4 ? G_IO_ERROR_CONNECTION_CLOSED :
                  mode == 5 ? G_IO_ERROR_CANCELLED :
                  mode == 6 ? G_IO_ERROR_BUSY : G_IO_ERROR_INVALID_DATA;
      g_assert_null (result.response);
      g_assert_error (result.error, G_IO_ERROR, code);
      if (mode == 3 || mode == 4) g_assert_cmpuint (server.request_bytes, ==, 0);
    }
  response_free (result.response);
  g_clear_error (&result.error);
  g_socket_listener_close (listener);
  g_assert_cmpint (g_unlink (path), ==, 0);
  g_assert_cmpint (g_rmdir (directory), ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/engine/codec", test_codec);
  g_test_add_func ("/engine/protocol", test_protocol);
  g_test_add_data_func ("/engine/enrollment/early-complete", GINT_TO_POINTER (FALSE), test_enrollment);
  g_test_add_data_func ("/engine/enrollment/beyond-target", GINT_TO_POINTER (TRUE), test_enrollment);
  g_test_add_func ("/engine/verify-results", test_verify_results);
  g_test_add_func ("/engine/cancel-retained-retry", test_cancel_retained_retry);
  g_test_add_data_func ("/engine/cancel-step", GINT_TO_POINTER (FALSE), test_cancel);
  g_test_add_data_func ("/engine/cancel-open", GINT_TO_POINTER (TRUE), test_cancel);
  g_test_add_func ("/engine/cleanup-failure", test_cleanup_failure);
  const gchar *cases[] = { "success", "short-header", "short-payload", "peer-uid",
                           "peer-restart", "cancel-read", "busy" };
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/engine/transport/%s", cases[i]);
      g_test_add_data_func (name, GUINT_TO_POINTER (i), test_transport);
    }
  return g_test_run ();
}
