
https://crypto.stackexchange.com/questions/53104/is-it-safe-to-store-both-the-aes-related-data-and-the-pbkdf2-related-data-excep?rq=1

 * Get password from command line; twice for encoding, once for decoding.
 * Implement environment passing?: not password, but private key & params.
    * This does not work for decrypt - needs params from the files.
    * Need to do something like ssh-agent? 
 * delete the output file if interrupted (ctrl-c)
 * maybe handle sigpipe?
 * config file?


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


TODO: Test using more common methods - actually running the executable
 * std::process only allows piping File to stdin, or going the spawn-write-wait path
   (https://doc.rust-lang.org/std/process/struct.Stdio.html)
   * No way to create anon pipe in std, although std uses it internally, though libc::pipe
     (https://github.com/rust-lang/rust/blob/master/src/libstd/sys/unix/pipe.rs)
   * nix crate provides pipe2 https://docs.rs/nix/0.14.1/nix/unistd/fn.pipe2.html
   * tempfile crate - provides tempfile() function that can be used to pipe into stdin.
   -> Decided to go with tempfile route and standard lib functions.
 * Process execution helpers:
   * duct crate https://docs.rs/duct/0.12.0/duct/struct.Expression.html
     - does not allow providing string as stdin, otherwise convenient with cmd!("name", "arg1", "arg2")
   -> Decided to just use standard lib functions; same convenience with a helper or two.
 * Test cmd helpers:
   https://docs.rs/assert_cmd/0.11.1/assert_cmd/
     adds cargo_bin to run the project binary -> reimplemented
     supplies buffer to stdin -> reimplemented
     assertions on output via `predicates` crate - not good. 
 * Good: will not need to rewrite when we do async.
 * Problem: need to control is_tty (see libc::isatty(stream.as_raw_fd()) == 1 )
   * Either need to add ENV variables , or create pseudo-tty
     * create pseudo-tty with 'nix' crate: use http://man7.org/linux/man-pages/man3/posix_openpt.3.html  (or openpty)
     -> Easier and safer to do ENV variables like MOCK_IS_TTY=stdin,stdout  
