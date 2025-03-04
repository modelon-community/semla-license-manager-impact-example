#ifndef MFL_jwt_util_H_
#define MFL_jwt_util_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/** @brief Runs a command with popen()
 * @return Returns bytes read on stdout on success (may be 0), or -1 on error.
 * *command_stdout is set to NULL on error.
 * Caller must free *command_stdout.
 */
int mfl_jwt_util_popen(char *command, char **command_stdout,
                       char *error_msg_buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MFL_jwt_util_H_ */
