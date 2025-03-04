#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mfl_common.h"
#include "mfl_interface.h"
#include "mfl_jwt.h"
#include "mfl_jwt_util.h"
#include "mfl_jwt_curl.h"

/** Runs a command with popen()
 * Returns bytes read on stdout on success (may be 0), or -1 on error.
 * *command_stdout is set to NULL on error.
 * Caller must free *command_stdout.
 */
int mfl_jwt_util_popen(char *command, char **command_stdout,
                       char *error_msg_buffer)
{
    int result = MFL_ERROR;
    int status = MFL_ERROR;
    char *command_with_stderr = NULL;
    int command_exit_status = -1;
    FILE *command_stdout_fp = NULL;
    int command_stderr_pipe_fd[2] = {-1, -1};
    char *command_stderr = NULL;
    FILE *command_stderr_fp = NULL;

    // ensure that command_stdout is always set to NULL on error
    *command_stdout = NULL;

    status =
        pipe2(command_stderr_pipe_fd,
              O_NONBLOCK); // do not block if no output is available on stderr
    if (status < 0) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: failed to call pipe() to create stderr pipe for "
                 "command. error message: '%s' command: '%s'",
                 strerror(errno), command);
        result = -1;
        goto error;
    }

    status =
        mfl_jwt_util_asprintf(error_msg_buffer, &command_with_stderr,
                              "%s 2>&%d", command, command_stderr_pipe_fd[1]);
    if (status != MFL_SUCCESS) {
        result = -1;
        goto error;
    }

    command_stderr_fp = fdopen(command_stderr_pipe_fd[0], "r");
    if (command_stderr_fp == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: failed to fdopen() command. error message: '%s' "
                 "command: '%s'",
                 strerror(errno), command);
        result = -1;
        goto error;
    }
    command_stdout_fp = popen(command_with_stderr, "r");
    if (command_stdout_fp == NULL) {
        snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                 "error: failed to popen() command. error message: '%s' "
                 "command: '%s'",
                 strerror(errno), command);
        result = -1;
        goto error;
    }

    result = mfl_jwt_util_read_file(command_stdout, command_stdout_fp,
                                    error_msg_buffer);
error:
    if (command_stdout_fp != NULL) {
        command_exit_status = pclose(command_stdout_fp);
        if (command_exit_status < 0) {
            snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                     "error: failed to pclose() command. %s", strerror(errno));
            result = -1;
        } else if (command_exit_status > 0) {
            mfl_jwt_util_read_file(
                &command_stderr, command_stderr_fp, error_msg_buffer);
            snprintf(error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                     "error: command failed. exit status: '%d' stderr "
                     "output: '%s' "
                     "command: '%s'",
                     strerror(errno), command_stderr, command);
            result = -1;
        }
    }
    if (command_stderr_fp != NULL) {
        status = fclose(command_stderr_fp); // also closes the underlying fd
                                            // command_stderr_pipe_fd[0]
        if (status != 0) {
            snprintf(
                error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                "error: failed to call fclose() to close the read file "
                "descriptor of stderr pipe for command. error message: '%s' "
                "command: '%s'",
                strerror(errno), command);
            result = -1;
        }
    }
    if (command_stderr_pipe_fd[1] != -1) {
        status = close(command_stderr_pipe_fd[1]);
        if (status < 0) {
            snprintf(
                error_msg_buffer, MFL_JWT_ERROR_MSG_BUFFER_SIZE,
                "error: failed to call close() to close the write file "
                "descriptor of stderr pipe for command. error message: '%s' "
                "command: '%s'",
                strerror(errno), command);
            result = -1;
        }
    }
    free(command_stderr);
    free(command_with_stderr);
    return result;
}
