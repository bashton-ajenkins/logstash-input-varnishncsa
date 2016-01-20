# encoding: utf-8
require "scanf"
require "logstash/inputs/threadable"
require "logstash/namespace"
require "socket" # for Socket.gethostname

# Read from varnish cache's shared memory log
class LogStash::Inputs::Varnishncsa < LogStash::Inputs::Threadable
  config_name "varnishncsa"

  config :instance, :validate => :string, :default => "default"

  trap("SIGINT") { @@reopen = 1}

  Logline = Struct.new(
    :df_H,     # %H, Protocol version
    :df_U,     # %U, URL path
    :df_q,     # %q, query string
    :df_b,     # %b, Bytes
    :df_h,     # %h (host name / IP adress)
    :df_m,     # %m, Request metho
    :df_s,     # %s, Status
    :df_t,     # %t, Date and time, received
    :df_u,     # %u, Remote user
    :df_ttfb,  # Time to first byte
    :df_D,     # %D, time taken to serve the request,
              # in microseconds, also used for %T
    :df_hitmiss,   # Whether this is a hit or miss
    :df_handling,  # How the request was handled (hit/miss/pass/pipe)
    :active,     # Is log line in an active trans
    :complete,     # Is log line complete
    :bitmap,    # Bitmap for regex matches
    :req_headers, # Request headers
    :resp_headers, # Response headers
    :vcl_log,     # VLC_Log entries
  )

  public
  def register
    require 'varnish'
    @lp = Logline.new
    clean_logline
    @lp[:df_hitmiss] = nil
    @lp[:df_handling] = nil
    @lp[:active] = false
    @lp[:complete] = false
    @vd = Varnish::VSM.VSM_New
    @@reopen = 0
    Varnish::VSL.VSL_Setup(@vd)
    if Varnish::VSM.VSM_n_Arg(@vd, @instance) != 1
      @logger.warn("varnishlog exception: #{e.inspect}")
    end
    Varnish::VSL.VSL_Open(@vd, 1)
  end # def register

  def run(queue)
    @q = queue
    @hostname = Socket.gethostname
    # callback = Proc.new { |*args| h_ncsa(*args) }
    Varnish::VSL.VSL_Dispatch(@vd, self.method(:h_ncsa).to_proc, FFI::MemoryPointer.new(:pointer))
  end # def run

  private
  def clean_logline(tag = '')
    @lp[:df_H]         = nil
    @lp[:df_U]         = nil
    @lp[:df_q]         = nil
    @lp[:df_b]         = nil
    @lp[:df_h]         = nil
    @lp[:df_m]         = nil
    @lp[:df_s]         = nil
    @lp[:df_u]         = nil
    @lp[:df_ttfb]      = nil
    @lp[:req_headers]  = []
    @lp[:resp_headers] = []
    @lp[:vcl_log]      = []
  end

  def collect_client(tag, str)
    case tag
    # Collect Client
    when :reqstart
      if @lp[:active] || @lp[:df_h] != nil
        clean_logline(tag)
      end
      @lp[:active] = true;
      @lp[:df_h] = str.split(' ').first
    when :rxrequest
      if @lp[:active]
        if @lp[:df_m] != nil
          clean_logline(tag)
        else
          @lp[:df_m] = str
        end
      end
    when :rxurl
      if @lp[:active]
        if @lp[:df_U] != nil || @lp[:df_q] != nil
          clean_logline(tag)
        else
          qs = str.index('?')
          if qs
            @lp[:df_U] =  str[0, qs]
            @lp[:df_q] =  str[qs, str.length]
          else
            @lp[:df_U] =  str
          end
        end
      end
    when :rxprotocol
      if @lp[:active]
        if @lp[:df_H] != nil
          clean_logline(tag)
        else
          @lp[:df_H] = str
        end
      end
    when :txstatus
      if @lp[:active]
        if @lp[:df_s] != nil
          clean_logline(tag)
        else
          @lp[:df_s] = str
        end
      end
    when :rxheader || :txheader
      if @lp[:active]
        split = str.index(':')
        if !split == nil
          if tag == :rxheader && str[0, split] == "Authorization" && str[split+2, str.length] == "basic"
            @lp[:df_u] = str
          end
        else
          if tag == :rxheader
            @lp[:req_headers].push({str[0, split] => str[split+2, str.length]})
          else
            @lp[:resp_headers].push({str[0, split] => str[split+2, str.length]})
          end
        end
      end
    when :vcl_log
      if @lp[:active]
        split = str.index(':')
        if !split == nil
          @lp[:vcl_log].push({str[0, split] => str[split+2, str.length]})
        end
      end
    when :vcl_call
      if @lp[:active]
        if str == "hit"
          @lp[:df_hitmiss] = "hit"
          @lp[:df_handling] = "hit"
        elsif str == "miss"
          @lp[:df_hitmiss] = "miss"
          @lp[:df_handling] = "miss"
        elsif str == "pass"
          @lp[:df_hitmiss] = "miss"
          @lp[:df_handling] = "pass"
        elsif str == "pipe"
          clean_logline(tag)
        end
      end
    when :length
      if @lp[:active]
        if @lp[:df_b] != nil
          clean_logline(tag)
        else
          @lp[:df_b] = str
        end
      end
    when :sessionclose
      if @lp[:active]
        if str ==  "pipe" || str ==  "error"
          clean_logline(tag)
        end
      end
    when :reqend
      t_req   = str.scanf("%*u %f %f %*u.%*u %s")
      t_start = t_req[0]
      t_end   = t_req[1]
      ttfb    = t_req[2]
      if @lp[:active]
        @lp[:df_ttfb] = ttfb
        @lp[:df_D] = t_end - t_start
        @lp[:df_t] = Time.at(t_start)
        @lp[:complete] = true
      end
    end
  end

  def collect_backend(tag, str)
    case tag
    # Collect Backend
    when :backendopen
      if @lp[:active] || @lp[:df_h] != nil
        clean_logline(tag)
      end
      @lp[:active] = true;
      @lp[:df_h]   = str.split(' ')[1]
    when :txrequest
      if @lp[:active]
        if @lp[:df_m] != nil
          clean_logline(tag)
        else
          @lp[:df_m] = str
        end
      end
    when :txurl
      if @lp[:active]
        if @lp[:df_U] != nil || @lp[:df_q] != nil
          clean_logline(tag)
        else
          qs = str.index('?')
          if qs
            @lp[:df_U] =  str[0, qs]
            @lp[:df_q] =  str[qs, str.length]
          else
            @lp[:df_U] =  str
          end
        end
      end
    when :txprotocol
      if @lp[:active]
        if @lp[:df_H] != nil
          clean_logline(tag)
        else
          @lp[:df_H] = str
        end
      end
    when :rxstatus
      if @lp[:active]
        if @lp[:df_s] != nil
          clean_logline(tag)
        else
          @lp[:df_s] = str
        end
      end
    when :rxheader
      if @lp[:active]
        split = str.index(':')
        if str[0, split] == 'Content-Length'
          @lp[:df_b] = str[split+2, str.length]
        elsif str[0, split] == 'Date'
          @lp[:df_t] = DateTime.strptime(str[split+2, str.length], "%a, %d %b %Y %T %Z")
          if @lp[:df_t] == nil
            clean_logline(tag)
          end
        end
      end
    when :txheader
      if @lp[:active]
        split = str.index(':')
        @lp[:req_headers].push({str[0, split] => str[split+2, str.length]})
      end
    when :backendclose || :backendreuse
      if @lp[:active]
        @lp[:complete] = true
      end
    end
  end

  def h_ncsa(priv, tag, fd, len, spec, ptr, bitmap)
    begin
      str = ptr.read_string(len)
      if spec == :spec_client
        collect_client(tag, str)
      elsif spec == :spec_backend
        collect_backend(tag, str)
      else
        return @@reopen
      end
      if !@lp[:complete]
        return @@reopen
      end
      # We have a complete data set - log a line
      headers = Hash.new
      if @lp[:resp_headers] != []
        headers = @lp[:resp_headers].reduce Hash.new, :merge
      elsif @lp[:req_headers] != []
        headers = @lp[:req_headers].reduce Hash.new, :merge
      end
      if !@lp[:df_h].nil?
        event = LogStash::Event.new("message" => "[#{@lp[:df_t].to_s}] http://#{headers['Host'].to_s}#{@lp[:df_U].to_s}#{@lp[:df_q]} #{@lp[:df_h]}", "host" => @hostname)
        decorate(event)

        event["varnish_spec"]    = spec.to_s
        event["clientip"]        = headers['X-Client-IP'].nil? ? headers['X-Forwarded-For'].nil? ? '' : headers['X-Forwarded-For'].split(',').first : headers['X-Client-IP']
        event["timestamp"]       = @lp[:df_t].to_s
        event["vhost"]           = headers['Host']
        event["ident"]           = '-'
        event["auth"]            = @lp[:df_u].to_s
        event["verb"]            = @lp[:df_m].to_s
        event["request"]         = "#{@lp[:df_U].to_s}#{@lp[:df_q]}"
        event["httpversion"]     = @lp[:df_H].to_s
        event["rawrequest"]      = "#{@lp[:df_m]} #{@lp[:df_U].to_s}#{@lp[:df_q]} #{@lp[:df_s]}"
        event["response"]        = @lp[:df_s].to_s
        event["bytes"]           = @lp[:df_b].to_s
        event["referrer"]        = headers['Referer']
        event["agent"]           = headers['User-Agent']
        event["X-Forwarded-For"] = headers['X-Forwarded-For']
        event["hitmiss"]         = @lp[:df_hitmiss]
        event["handling"]        = @lp[:df_handling]
        event["headers"]         = headers
        begin
          payload = event.to_json
        rescue Encoding::UndefinedConversionError, ArgumentError
          puts "FAILUREENCODING : #{@lp[:df_m]} #{@lp[:df_U].to_s}#{@lp[:df_q]} #{@lp[:df_s]}"
          @logger.error("Failed to convert event to JSON. Invalid UTF-8, maybe?",
                        :event => event.inspect)
          return @@reopen
        end

        @q << event

      end
      # clean up
      clean_logline
      @lp[:df_hitmiss] = nil
      @lp[:df_handling] = nil
      @lp[:active] = false
      @lp[:complete] = false
    rescue => e
      @logger.warn("varnishlog exception: #{e.inspect} #{e.backtrace}")
    ensure
      return @@reopen
    end
  end
end # class LogStash::Inputs::Stdin
