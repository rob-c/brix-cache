/*
 * multipart_complete.c — S3 CompleteMultipartUpload handler aggregation file.
 *
 * WHAT: This file is a C include-aggregator that owns the S3 multipart complete module unit.
 *   It includes three named fragment files, each implementing one sub-operation of CompleteMultipartUpload:
 *     - multipart_complete_list_parts.c:  parses and validates the <Part> entries from the XML body
 *       (part numbers + ETags), returning InvalidArgument for missing/invalid part entries.
 *     - multipart_complete_list_uploads.c: optional — lists remaining in-progress uploads when a
 *       CompleteMultipartUpload request includes <ListRemainingUploads>true</ListRemainingUploads>.
 *     - multipart_complete_upload_part_copy.c: handles UploadPartCopy sub-operation within the POST body,
 *       copying a part from a source object into the staging directory of an active multipart upload.
 *   Do not compile these fragments directly; they are included by multipart_complete.c which owns
 *   the nginx module unit registration and dispatch logic.
 *
 * WHY: Splitting CompleteMultipartUpload handlers into named fragments keeps each unit small and approachable,
 *      preserving original code structure and inline comments while allowing independent review. The aggregator file
 *      ensures all fragments compile as a single module unit with proper include ordering.
 */

#include "multipart_complete_list_parts.c"
#include "multipart_complete_list_uploads.c"
#include "multipart_complete_upload_part_copy.c"
