#ifndef PIDGEIOT_PIGEON_FOTA_RESUME_H_
#define PIDGEIOT_PIGEON_FOTA_RESUME_H_

#include <stddef.h>
#include <stdint.h>

#include <pigeon.h>

/*
 * FOTA download-resume persistence (CONFIG_PIGEON_FOTA_RESUME): a tiny
 * per-version NVS/settings record binding the flash-write backend's own
 * persisted stream progress to the firmware version it belongs to, plus the
 * pure reconcile logic deciding what a new pigeon_fota_apply() call may
 * safely resume. Split out of pigeon_fota.c so the reconcile/record logic
 * can be exercised by tests/fota_resume on native_sim, where the MCUboot
 * dependencies of the rest of the FOTA path can't build.
 *
 * Deliberately NOT persisted: any sha256 streaming state. On resume the
 * digest is rebuilt by re-reading the already-flushed slot bytes from flash
 * (seconds of flash reads) rather than serializing a crypto context --
 * see pigeon_fota_apply()'s resume path.
 */

/* Settings keys. The record key holds struct pigeon_fota_resume_record.
 * The stream key is only used by the default (upstream flash_img) backend,
 * as the stream_flash_progress_save/_load key holding the backend's own
 * flushed-bytes counter; the NCS backend persists that counter itself under
 * its own "dfu/<target>" key (dfu_target_stream.c,
 * CONFIG_DFU_TARGET_STREAM_SAVE_PROGRESS). */
#define PIGEON_FOTA_RESUME_RECORD_KEY "pigeon/fota/resume"
#define PIGEON_FOTA_RESUME_STREAM_KEY "pigeon/fota/sf"

struct pigeon_fota_resume_record {
  /* NUL-terminated target version this progress belongs to; "" = no
   * record (nothing resumable). */
  char version[PIGEON_FOTA_VERSION_MAX];
  /* Bytes confirmed FLUSHED to the secondary slot -- never bytes-received:
   * a reboot loses any write-block tail still buffered in RAM, so a
   * received-bytes offset would resume past a hole. Diagnostic cross-check
   * only at reconcile time; the backend's own restored counter is what
   * actually positions the write stream (see
   * pigeon_fota_resume_reconcile()). */
  uint32_t offset;
};

enum pigeon_fota_resume_action {
  /* No usable prior progress -- download from byte 0 (backend state is
   * already clean). */
  PIGEON_FOTA_RESUME_FRESH,
  /* Prior progress is valid for this target -- resume from *resume_from. */
  PIGEON_FOTA_RESUME_CONTINUE,
  /* Persisted state is stale or inconsistent (version changed, offset
   * past the declared image size, or backend progress with no record
   * vouching for it) -- the caller must clear the record AND the backend's
   * persisted progress, reset the backend to a fresh session, and download
   * from byte 0. */
  PIGEON_FOTA_RESUME_INVALIDATE,
};

/*
 * Decides whether a download of target_version/total_size may resume.
 *
 * backend_offset is the flash-write backend's own view of how many bytes
 * are already flushed to the slot, queried AFTER backend (re)init restored
 * any persisted stream progress -- it is the only offset the stream can
 * actually continue from (stream writes are append-only; there is no seek).
 * rec is the last-loaded record; the two normally agree, and when they
 * don't, the flushed-only guarantee of the backend counter (see the
 * source-trace comments at the call sites in pigeon_fota.c) plus the
 * full-image sha256 verify at completion make backend_offset the safe
 * choice in both directions -- rec's offset is a logged cross-check, and
 * rec's job is binding that progress to a version.
 *
 * Pure function: no settings/flash access, exercised by tests/fota_resume.
 */
enum pigeon_fota_resume_action pigeon_fota_resume_reconcile(
    const struct pigeon_fota_resume_record *rec, const char *target_version, size_t total_size,
    size_t backend_offset, size_t *resume_from
);

/*
 * Record persistence, all best-effort wrappers over the settings subsystem
 * (the app must provide a settings backend -- see PIGEON_FOTA_RESUME's
 * Kconfig help). load() zeroes *rec when no record exists and returns 0;
 * a negative return means settings themselves failed and *rec is zeroed.
 */
int pigeon_fota_resume_load(struct pigeon_fota_resume_record *rec);
int pigeon_fota_resume_save(const char *version, size_t offset);
int pigeon_fota_resume_clear(void);

#endif /* PIDGEIOT_PIGEON_FOTA_RESUME_H_ */
