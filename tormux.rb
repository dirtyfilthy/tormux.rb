#!/usr/bin/ruby

############
#
# tormux.rb v0.1 by dirtyfilthy, latest code at http://github.com/dirtyfilthy/tormux.rb
#
############


require 'socket'
require 'base64'
require 'time'
require 'optparse'

class TorCtl

  class Reply
    attr_accessor :code
    attr_accessor :lines

    def to_s
      return "#{code} #{lines.join("\n")}"
    end

  end

  class NetworkStatus
    attr_accessor :nick
    attr_accessor :idhash
    attr_accessor :orhash
    attr_accessor :ip
    attr_accessor :orport
    attr_accessor :dirport
    attr_accessor :flags
    attr_accessor :updated
    attr_accessor :idhex

    def idhash=(r)
      @idhex=Base64.decode64(r+"=").unpack("H*").first
      @idhash=r
    end

  end
  

  def initialize(options = {}, &block)
    @options = options.dup
    @host    = (@options.delete(:host)    || '127.0.0.1').to_s
    @port    = (@options.delete(:port)    || 9051).to_i
    @num_circuits = (@options.delete(:circuits)    || 10).to_i
    
    @num_guards = (@options.delete(:guards)    || 10).to_i
    @authenticated=false
    @event_queue=[]
    @routers = []
    @exits = []
    @guards = []
    @gc=0
    
    @xc=0
    @pool = []
    @cur_circuit=0
    connect
    authenticate
    @max_onions_pending=get_conf("MaxOnionsPending")
    @new_circuit_period=get_conf("newcircuitperiod")
    @new_circuit_dirtiness=get_conf("newcircuitdirtiness")
    set_conf "__DisablePredictedCircuits",1
    set_conf "MaxOnionsPending", 0
    set_conf "newcircuitperiod", 99999999
    set_conf "maxcircuitdirtiness", 99999999
    set_conf "__LeaveStreamsUnattached",1
  
    
    trap("INT"){ shutdown }
   
  end


  # tidy up after ourselves

  def shutdown
    puts "shutting down"
    @pool = []
    close_current_circuits
    set_conf "__DisablePredictedCircuits",0
    set_conf "__LeaveStreamsUnattached",0
    set_conf "MaxOnionsPending", @max_onions_pending
    set_conf "newcircuitperiod", @new_circuit_period
    set_conf "newcircuitdirtiness", @new_circuit_dirtiness
    @stop_now=true
  end

  def close_current_circuits
    puts "killing old circuits"
    r=send_command("GETINFO","circuit-status")
    r.lines.shift
    r.lines.each do |l|
      if l=~/\d+ BUILT/
        send_command("CLOSECIRCUIT",l.scan(/^\d+/).first)
      end
    end
  end

  def build_circuit
    f=@guards[@gc]
    x=@exits[@xc]
    return nil if x.nil?
    extend_circuit(0,["$#{f.idhex}","$#{x.idhex}"])
    @gc=(@gc+1) % @guards.size
    @xc=(@xc+1) % @exits.size
  end

  def build_circuits
    puts "spinning up #{@num_circuits} circuits"
    @guards=@guards.shuffle[0..(@num_guards-1)]
    @exits.shuffle
    @num_circuits.times do
      build_circuit
    end
  end

  def get_routers
    puts "gettings tor directory"
    r=send_command("GETINFO","ns/all")
    r.lines.shift
    ns=nil
    loop do
      line=r.lines.shift
      break if line=="OK" or line.nil?
      case line[0]
      when 'r'
        @routers << ns unless ns.nil?
        ns=NetworkStatus.new
        ns_ary=line.scan(/r (\S+) (\S+) (\S+) (\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) (\d+\.\d+\.\d+\.\d+) (\d+) (\d+)/).first
        ns.nick      = ns_ary[0]
        ns.idhash    = ns_ary[1]
        ns.orhash    = ns_ary[2]
        ns.updated   = Time.parse(ns_ary[3])
        ns.ip        = ns_ary[4]
        ns.orport    = ns_ary[5]
        ns.dirport   = ns_ary[6]
      when 's'
        ns.flags     = line.split
        ns.flags.shift
      end
    end
    @exits=@routers.select{|r| r.flags.include?("Exit")}
    @guards=@routers.select{|r| r.flags.include?("Guard")} - @exits
    puts "#{@exits.count} exits & #{@guards.count} guards found"
  end

  def extend_circuit(circuit_id, hops)
    args=[circuit_id]
    hops=[hops] if hops.is_a?(String)
    args<<hops.join(",")
    r=send_command("EXTENDCIRCUIT", *args);
    raise "failed to extend circuit '#{r.lines[0]}'"  if !(r.lines[0]=~/EXTENDED/)
    return r.lines[0].scan(/EXTENDED (\S*)/).first.first
  end

  def connect
    puts "connecting to tor control #{@host}:#{@port}"
    @socket = TCPSocket.new(@host, @port)
    @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    self
  end

  def send_command(command, *args)
    authenticate unless authenticated?
    send_line(["#{command.to_s.upcase}", *args].join(' '))
    loop do
      r=read_reply
      if(r.code[0]=='6')
        @event_queue<<r
      else
        return r
      end
    end
  end

  def send_line(line)
    @socket.write(line.to_s + "\r\n")
    @socket.flush
  end



  def read_line
    @socket.readline.chomp
  end

  def read_reply
    reply=Reply.new
    lines = []
    loop do
    line=read_line
    code=line[0..2]
    mode=line[3]
    line=line[4..-1]
    lines << line
    case mode
    when ' '
      reply.lines=lines
      reply.code=code
      return reply
    when '-'
      reply.code=code
    when '+'
      while((r=read_line)!=".") do
        lines << r
      end
    end
  end
  end

  def authenticated?
    return (@authenticated==true)
  end


  def set_conf(key,value)
    send_command("SETCONF","#{key}=#{value}")
  end



  def get_conf(key)
    r=send_command("GETCONF","#{key}")
    return r.lines[0].split("=")[1]
  end



  def set_events(events)
    args=["EXTENDED"]
    args<<events
    send_command("SETEVENTS",*args)
  end

  def authenticate(cookie = nil)
    puts "authenticating"
    cookie ||= @options[:cookie]
    send(:send_line, cookie ? "AUTHENTICATE \"#{@cookie}\"" : "AUTHENTICATE")
    case reply = read_line
    when '250 OK' then @authenticated = true
    else raise "Couldn't auth: #{reply}"
  end
  self
  end

  def process_events
    while(e=@event_queue.shift) do
      if e.code=="650" and e.lines.first=~/STREAM \d+ NEW/
        next if @pool.size==0
        stream_id=e.lines.first.scan(/STREAM (\d+) NEW/).first.first
        @cur_circuit=(@cur_circuit+1) % @pool.size
        next if @pool[@cur_circuit].nil?
        p=send_command("ATTACHSTREAM",stream_id,@pool[@cur_circuit])
      end

      if e.code=="650" and e.lines.first=~/STREAM \d+ DETACHED/
        next if @pool.size==0
        stream_id=e.lines.first.scan(/STREAM (\d+) DETACHED/).first.first
        @cur_circuit=(@cur_circuit+1) % @pool.size
        next if @pool[@cur_circuit].nil?
        p=send_command("ATTACHSTREAM",stream_id,@pool[@cur_circuit])
      end


      if e.code=="650" and e.lines.first=~/CIRC \d+ BUILT/
        circ = e.lines.first.scan(/CIRC (\d+) BUILT/).first.first
        @pool << circ
        puts "built circuit #{circ}"
      end



      if e.code=="650" and e.lines.first=~/CIRC \d+ CLOSED/
        circ = e.lines.first.scan(/CIRC (\d+) CLOSED/).first.first
        build_circuit if @pool.delete(circ)
      end


      if e.code=="650" and e.lines.first=~/CIRC \d+ FAILED/
        build_circuit
      end

    end
  end

  def main_loop
    loop do 
      break if @stop_now
      r=read_reply
      @event_queue << r if r.code[0]=='6'
      process_events
    end
    @socket.close
  end

end
options={}
options[:circuits]=0
opts=OptionParser.new do |opts|

  opts.banner = <<-eos
tormux v0.1 -- simple controller to reverse multiplex between tor exit nodes
Usage: ./tormux.rb [options] -x EXITNODES
NOTE: You will need to enable ControlPort in your torrc and possibly set a password,
tormux will also kill any current tor circuits.
  eos
  opts.separator ""
  opts.separator "Options:"
  opts.on("-p", "--password PASS", "the password for tor control (plaintext)") do |pass|
    options[:cookie] = pass
  end

  opts.on("-x", "--exits EXITNODES", "number of exit nodes to spin up") do |ex|
    options[:circuits] = ex.to_i
  end

  opts.on("-g", "--guards GUARDNODES", "number of guards to use (default 10)") do |g|
    options[:guards] = g.to_i
  end


  opts.on("-t", "--tor-control IP:PORT", "the tor control port to connect to (default 127.0.0.1:9051)") do |t|
    options[:host]=t.split(":")[0]
    options[:port]=t.split(":")[1]
  end

end
opts.parse!
if options[:circuits]==0
  puts opts
  exit(0)
end
t=TorCtl.new(options)

t.set_events(["STREAM", "CIRC", "ADDRMAP", "NEWDESC"]);
t.close_current_circuits
t.get_routers
t.build_circuits
t.main_loop
