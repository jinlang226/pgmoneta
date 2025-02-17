/*
 * Copyright (C) 2022 Red Hat
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PGMONETA_WORKFLOW_H
#define PGMONETA_WORKFLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define WORKFLOW_TYPE_BACKUP 0

typedef int (* setup)(int, char*);
typedef int (* execute)(int, char*);
typedef int (* teardown)(int, char*);

struct workflow
{
   setup setup;
   execute execute;
   teardown teardown;

   struct workflow* next;
};

/**
 * Create a workflow
 * @param workflow_type The workflow type
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create(int workflow_type);

/**
 * Delete the workflow
 * @param workflow The workflow
 * @return 0 upon success, otherwise 1
 */
int
pgmoneta_workflow_delete(struct workflow* workflow);

/**
 * Create a workflow for the local storage engine
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_local_storage(void);

/**
 * Create a workflow for the base backup
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_basebackup(void);

/**
 * Create a workflow for GZIP
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_gzip(void);

/**
 * Create a workflow for Zstandard
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_zstd(void);

/**
 * Create a workflow for Lz4
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_lz4(void);

/**
 * Create a workflow for symlinking
 * @return The workflow
 */
struct workflow*
pgmoneta_workflow_create_link(void);

#ifdef __cplusplus
}
#endif

#endif
