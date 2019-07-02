P0:
 * Convert header to a real .proto file.
 * Implement the new file format, with tests.
 * Read password from stdin
   * Twice for encrypt, once for decrypt
 * Finalize basic command line usage: '-e, --encrypt', '-d, decrypt' 
    * If file is not given, show help
    * If encrypt/decrypt successful, replace file 
    *   copy attributes from the replaced file (owner, group, perms, access/mod times)
    * If target file already exists, error and skip.
    * Warning and skip if: symlink; already has extension, doesn't have supported ext
    * delete the output file on error or if interrupted (ctrl-c)
    * '-k, --keep' - keep the original file
    * '-f' - overwrite the destination file
    * '-c, --stdout, --to-stdout' - write to stdout; implies -k
 * Add finalization to AES256GCM - otherwise attacker can truncate the file and get a correct output.
 * Errors: tell which chunk is failed via context.
 * Make progress optional (command line)
 * Create a readme
 * Handle errors from threads.
 * Publish to github, /r/rust, hacker news.
 * Maybe compare with naive solution?
 * Remove sodiumoxide from deps, and, potentially, structopt (takes too much space)
 
P1:
 * Implement passing password via environment variable?: maybe not password, but private key & params.
    * This does not work for decrypt - needs params from the files.
    * Need to do something like ssh-agent? 
 * Support multithreading for supporting encoders (might be hard to share the state).
 * Add benchmarking
 * Add external authenticated data + ability to get it, with or without password.
   * Both attached and detached.
 * Adjustable chunk size, flush timeout / size (via command line args)
 * Initially write to an invisible tempfile in the same directory (using either tempfile crate or O_TMPFILE), then
   atomically make it visible.


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
