/*
 * Synthetic regression tests for NBIS print quality.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "fpi-image.h"
#include "fpi-minutiae.h"
#include "fp-print-private.h"

static FpPrint *
new_print (void)
{
  return g_object_ref_sink (g_object_new (FP_TYPE_PRINT,
                                         "driver", "synthetic",
                                         "device-id", "synthetic",
                                         "fpi-type", FPI_PRINT_NBIS,
                                         NULL));
}

/* These points are invented; no sensor, stored template or image is read. */
static FpImage *
new_image (guint count)
{
  FpImage *image = fp_image_new (160, 128);

  image->minutiae = g_ptr_array_new_with_free_func (g_free);
  for (guint i = 0; i < count; i++)
    {
      struct fp_minutia *point = g_new0 (struct fp_minutia, 1);

      point->x = 5 + (i % 20) * 7;
      point->y = 5 + (i / 20) * 10;
      point->direction = (i * 7) % 16;
      point->reliability = 1.0;
      g_ptr_array_add (image->minutiae, point);
    }

  return image;
}

static void
test_unusable_view (gconstpointer user_data)
{
  guint count = GPOINTER_TO_UINT (user_data);
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(FpImage) image = new_image (count);
  g_autoptr(GError) error = NULL;

  g_assert_false (fpi_print_add_from_image (print, image, &error));
  g_assert_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL);
  g_assert_cmpuint (print->prints->len, ==, 0);
  g_assert_null (fp_print_get_image (print));
}

static void
test_computable_view (gconstpointer user_data)
{
  guint count = GPOINTER_TO_UINT (user_data);
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(FpImage) image = new_image (count);
  g_autoptr(GError) error = NULL;
  struct xyt_struct *view;

  g_assert_true (fpi_print_add_from_image (print, image, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (print->prints->len, ==, 1);
  view = g_ptr_array_index (print->prints, 0);
  g_assert_cmpint (view->nrows, ==, count);
  g_assert_true (fp_print_get_image (print) == image);
}

static void
test_retry_preserves_existing_view (void)
{
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(FpImage) accepted = new_image (40);
  g_autoptr(FpImage) rejected = new_image (4);
  g_autoptr(GError) error = NULL;
  struct xyt_struct saved;

  g_assert_true (fpi_print_add_from_image (print, accepted, &error));
  g_assert_no_error (error);
  saved = *(struct xyt_struct *) g_ptr_array_index (print->prints, 0);
  g_assert_false (fpi_print_add_from_image (print, rejected, &error));
  g_assert_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL);
  g_assert_cmpuint (print->prints->len, ==, 1);
  g_assert_true (fp_print_get_image (print) == accepted);
  g_assert_cmpmem (print->prints->pdata[0], sizeof (saved), &saved, sizeof (saved));
}

static void
test_match_after_serialization (void)
{
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(FpImage) image = new_image (40);
  g_autoptr(FpPrint) restored = NULL;
  g_autofree guchar *bytes = NULL;
  gsize length;
  g_autoptr(GError) error = NULL;

  g_assert_true (fpi_print_add_from_image (print, image, &error));
  g_assert_no_error (error);
  g_assert_true (fp_print_serialize (print, &bytes, &length, &error));
  g_assert_no_error (error);
  restored = fp_print_deserialize (bytes, length, &error);
  g_assert_no_error (error);
  g_assert_nonnull (restored);
  g_assert_true (fp_print_equal (print, restored));
  g_assert_cmpint (fpi_print_bz3_match (restored, print, 40, &error), ==, FPI_MATCH_SUCCESS);
  g_assert_no_error (error);
}

static void
test_invalid_image (void)
{
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(FpImage) image = new_image (0);
  g_autoptr(GError) error = NULL;

  g_assert_false (fpi_print_add_from_image (print, NULL, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  g_clear_error (&error);
  g_assert_false (fpi_print_add_from_image (print, image, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA);
  g_assert_cmpuint (print->prints->len, ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_data_func ("/print/nbis/retry-1", GUINT_TO_POINTER (1), test_unusable_view);
  g_test_add_data_func ("/print/nbis/retry-2", GUINT_TO_POINTER (2), test_unusable_view);
  g_test_add_data_func ("/print/nbis/retry-3", GUINT_TO_POINTER (3), test_unusable_view);
  g_test_add_data_func ("/print/nbis/retry-4", GUINT_TO_POINTER (4), test_unusable_view);
  g_test_add_data_func ("/print/nbis/retry-9", GUINT_TO_POINTER (9), test_unusable_view);
  g_test_add_data_func ("/print/nbis/accept-10", GUINT_TO_POINTER (10), test_computable_view);
  g_test_add_data_func ("/print/nbis/accept-40", GUINT_TO_POINTER (40), test_computable_view);
  g_test_add_data_func ("/print/nbis/accept-200", GUINT_TO_POINTER (200), test_computable_view);
  g_test_add_func ("/print/nbis/retry-preserves-view", test_retry_preserves_existing_view);
  g_test_add_func ("/print/nbis/match-after-serialization", test_match_after_serialization);
  g_test_add_func ("/print/nbis/invalid-image", test_invalid_image);
  return g_test_run ();
}
