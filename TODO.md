
https://crypto.stackexchange.com/questions/53104/is-it-safe-to-store-both-the-aes-related-data-and-the-pbkdf2-related-data-excep?rq=1


 * delete the output file if interrupted



Questions:
 * How to add finalization to AES256-GCM?
 * Decide whether we should write authentication tags separately in the beginning.
   * PRO: easy to support stream mode, fast to check header,
   * CON: + 16 bytes, not really using AEAD mode (only separately)
   -> In the first data chunk
 * How to store authenticated data when it's attached (inside header or outside)?
  * Probably not chunked/streamed. But can be detached.
  -> Outside header.

P0:
 * Finalize basic command line usage: '-e, --encode, encode', '-d, decode' 
    * If file is not given, read from stdin; or show help
    * If output file is not given, replace file + copy attributes (owner, group, perms, access/mod times)
    * If target file already exists, error and skip.
    * Warning and skip if: symlink; already has extension, doesn't have supported ext
    * Out file option
 * Add finalization to AES256GCM - otherwise attacker can truncate the file and get a correct output.
 * Errors: tell which chunk is failed via context.
 * Read password from stdin and file
 * Make progress optional (command line)
 * Create a readme
 * Handle errors from threads.
 * Publish to github, /r/rust, hacker news.
 * Maybe compare with naive solution?
 * Remove sodiumoxide from deps, and, potentially, structopt (takes too much space)
 
P1:
 * Replace file with file.enc
    * '-S .suf, --suffix .suf' to use a different suffix.
    * '-k, --keep' - keep the original file
    * '-f' - overwrite the destination file
    * '-c, --stdout, --to-stdout' - write to stdout; implies -k
 * Support multithreading for supporting encoders (might be hard to share the state).
 * Add benchmarking
 * Add external authenticated data + ability to get it, with or without password.
 * Adjustable chunk size, flush timeout / size
 *  
