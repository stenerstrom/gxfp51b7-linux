/* SPDX-License-Identifier: LGPL-2.1-or-later
 * The original enclave owns template content and unseal validation. This codec
 * checks host compatibility and resource bounds without parsing biometric data.
 */
#define FP_COMPONENT "goodix_chicago_engine"
#include "goodix_chicago_engine.h"
#include <string.h>

typedef struct { gsize length; guint8 data[]; } EngineBytes;

void
chicago_engine_erase (gpointer data, gsize length)
{
  volatile guint8 *bytes = data;
  while (length--) *bytes++ = 0;
}

static void
engine_bytes_free (gpointer data)
{
  EngineBytes *owner = data;
  chicago_engine_erase (owner->data, owner->length);
  g_free (owner);
}

GBytes *
chicago_engine_bytes_new (const guint8 *data, gsize length)
{
  EngineBytes *owner;
  g_return_val_if_fail (data && length <= GXOE_PAYLOAD_MAX, NULL);
  owner = g_malloc (sizeof (*owner) + length);
  owner->length = length;
  memcpy (owner->data, data, length);
  return g_bytes_new_with_free_func (owner->data, length, engine_bytes_free, owner);
}

static gboolean
invalid_print (GError **error)
{
  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                       "Fingerprint is incompatible with this original Engine; enroll it again");
  return FALSE;
}

gboolean
chicago_engine_set_print (FpPrint *print, GBytes *sealed, GError **error)
{
  gsize length;
  const guint8 *bytes;
  g_autoptr(GBytes) owned = NULL;
  g_autoptr(GVariant) data = NULL;
  GVariant *array;
  if (!print || !sealed) return invalid_print (error);
  bytes = g_bytes_get_data (sealed, &length);
  if (length < GXOE_TEMPLATE_MIN || length > GXOE_TEMPLATE_MAX)
    return invalid_print (error);
  if (fpi_print_get_type (print) != FPI_PRINT_UNDEFINED &&
      fpi_print_get_type (print) != FPI_PRINT_RAW)
    return invalid_print (error);
  owned = chicago_engine_bytes_new (bytes, length);
  array = g_variant_new_from_bytes (G_VARIANT_TYPE ("ay"), owned, TRUE);
  data = g_variant_ref_sink (g_variant_new ("(susu@ay)", GXOE_ENROLL_MARKER,
                                           GXOE_TEMPLATE_SCHEMA, GXOE_ENGINE_SHA256,
                                           GXOE_PROFILE, array));
  if (fpi_print_get_type (print) == FPI_PRINT_UNDEFINED)
    fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", data, NULL);
  return TRUE;
}

GBytes *
chicago_engine_get_print (FpPrint *print, GError **error)
{
  g_autoptr(GVariant) data = NULL, blob = NULL;
  const gchar *marker, *engine;
  const guint8 *bytes;
  guint32 schema, profile;
  gsize length;
  if (!print || fpi_print_get_type (print) != FPI_PRINT_RAW ||
      fp_print_get_device_stored (print)) goto invalid;
  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE (CHICAGO_ENGINE_PRINT_TYPE)) ||
      g_variant_get_size (data) > GXOE_TEMPLATE_MAX + 256 ||
      !g_variant_is_normal_form (data)) goto invalid;
  g_variant_get (data, "(&su&su@ay)", &marker, &schema, &engine, &profile, &blob);
  if (strcmp (marker, GXOE_ENROLL_MARKER) || schema != GXOE_TEMPLATE_SCHEMA ||
      strcmp (engine, GXOE_ENGINE_SHA256) || profile != GXOE_PROFILE) goto invalid;
  bytes = g_variant_get_fixed_array (blob, &length, 1);
  if (length < GXOE_TEMPLATE_MIN || length > GXOE_TEMPLATE_MAX) goto invalid;
  return chicago_engine_bytes_new (bytes, length);
invalid:
  invalid_print (error);
  return NULL;
}
