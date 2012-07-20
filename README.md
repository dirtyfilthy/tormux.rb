# tormux.rb 

tormux.rb is a single file, zero dependency ruby tor controller for multiplexing outgoing connections between tor exit nodes. This means it will build and maintain one circuit for each of the number of exit nodes you specify, and round robin your outgoing tor connections between them automatically.

## INSTALLATION

If you have ruby and tor you already have everthing you need. simply "chmod +x tormux.rb", uncomment the ControlPort line in your /etc/tor/torrc and restart tor. You may also want to add a password to your tor controller service. To do this, run "tor --hash-password YOURPASS" and copy & paste the resulting hash into your torrc with a line like "HashedControlPassword 16:8129231FD5FB5CB460C8223024AD08B5B268596F1CF0142EFCA99C9150"

## USAGE

tormux.rb builds 2 hop circuits and does not support .onion addresses. It will kill any current tor circuits and connections you have running. The number of guards refers to the the number of entry nodes you're going to use, this doesn't have to (and probably shouldn't) be equal to the number of exit nodes. It's usable as soon as you start seeing "built circuit" lines in the output. Simply use tor as per normal, each connection you make will be automatically routed to a different exit node in a round robin fashion.

## OPTIONS

    ./tormux.rb
    tormux v0.1 -- simple controller to multiplex between tor exit nodes
    Usage: ./tormux.rb [options] -x EXITNODES
    NOTE: You will need to enable ControlPort in your torrc and possibly set a password,
    tormux will also kill any current tor circuits.

    Options:
        -p, --password PASS              the password for tor control (plaintext)
        -x, --exits EXITNODES            number of exit nodes to spin up
        -g, --guards GUARDNODES          number of guards to use (default 10)
        -t, --tor-control IP:PORT        the tor control port to connect to (default 127.0.0.1:9051)
