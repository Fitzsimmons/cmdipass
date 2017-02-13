# cmdipass
Command line client for KeePass via the KeePassHttp plugin

## Intro

Copy and pasting secrets to the command line sucks. How about we just pull them out of keepass, and save ourselves the trouble? As a bonus, we still get a useful entry in our shell's history, without leaking the secret.

Before:

```
justinf@wyvern:/home/justinf/src/cmdipass
master ✔ > vault auth -method=github token=redacted1234
Successfully authenticated! You are now logged in.

justinf@wyvern:/home/justinf/src/cmdipass
master ✔ > history | grep github | tail -n 1
10037  vault auth -method=github token=redacted1234
```

After:
```
justinf@wyvern:/home/justinf/src/cmdipass
master ✔ > vault auth -method=github token=$(cmdipass get-one github-token --index=0 --password-only)
Successfully authenticated! You are now logged in.

justinf@wyvern:/home/justinf/src/cmdipass
master ✔ > history | grep github | tail -n 1
10043  vault auth -method=github token=$(cmdipass get-one github-token --index=0 --password-only)
```

`cmdipass` uses [KeePassHttp](https://github.com/pfn/keepasshttp) to securely fetch secrets from [KeePass](http://keepass.info/). The first time you execute `cmdipass`, it will attempt to register with KeePassHttp. It also works with [MacPass](https://github.com/mstarke/MacPass) and [MacPassHTTP](https://github.com/MacPass/MacPassHTTP), although with some [caveats](#macpass-caveats).

![Screenshot of the trust dialog](trust.png)

From then on, you'll get a notification whenever cmdipass is used to look up a value.

## Usage

```
cmdipass get <search-string>
cmdipass get-one <search-string> (--index=<index> | --uuid=<uuid>) [--password-only | --username-only]
cmdipass --version
cmdipass (-h | --help)

Options:
  -h --help         Show this screen.
  --version         Show version.
  --index=<index>   Select the entry at this 0-indexed location.
  --uuid=<uuid>     Select the entry with this uuid.
  --password-only   Print only the password.
  --username-only   Print only the username.
```

## Downloads

I haven't published any binary releases yet, but I will soon! Until then, see the [Compiling from source](#compiling-from-source) secton.

## Compiling from source

You'll need rust. I recommend using [rustup](https://www.rustup.rs/) to get it, although you may want to use an [alternative installation method](https://github.com/rust-lang-nursery/rustup.rs/#other-installation-methods) to avoid the `curl | bash` anti-pattern.

Then, just clone the repo and run `cargo build` from the root of the repo. Your executable will be available at `target/debug/cmdipass`. Debug build recommended since performance is not a significant factor and it'll help you submit a useful bug report when something goes wrong. :smile:

## MacPass caveats

MacPassHTTP currently expects there to be a scheme present in the string that is used to search the database. [MacPassHTTP#31](https://github.com/MacPass/MacPassHTTP/issues/31). There is also a defect that will cause the entire database to be returned when there is no match with the search string. [MacPassHTTP#30](https://github.com/MacPass/MacPassHTTP/issues/30). You can work around these issues by adding a bogus scheme to your cmdipass query, e.g. `cmdipass get-one http://github-token`. You do not need to alter the entry in MacPass.

## Contributing

Happy to accept issues and pull requests.

## Contact

Chat with me on keybase or one of the other accounts I've verified: https://keybase.io/jsfitzsimmons/
