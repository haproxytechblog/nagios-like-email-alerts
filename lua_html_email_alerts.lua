-- send nagios-like html email alerts to report server state changes
-- this is provided as an example, the code is probably incomplete
-- (only SERVER_STATE events are reported) and not very clean (html
-- generation part is semi-hardcoded).
--
-- To be loaded using "lua-load" from haproxy configuration to handle
-- email-alerts directly from lua and disable legacy tcpcheck implementation.

local SYSLOG_LEVEL = {
	["EMERG"] = 0,
	["ALERT"] = 1,
	["CRIT"] = 2,
	["ERROR"] = 3,
	["WARN"] = 4,
	["NOTICE"] = 5,
	["INFO"] = 6,
	["DEBUG"] = 7
}

local mailqueue = core.queue()

-- smtp : send SMTP message
--
-- Copyright 2018 Thierry Fournier
--
-- This function is compliant with HAProxy cosockets
-- EHLO was replaced with HELO for better compatibility with
-- basic mail server implementations
--
-- <server> should contain the full server address (including port) in the
-- same format used in haproxy config file. It will be passed as it is to
-- tcp::connect() without explicit port argument. See Socket.connect()
-- manual for more information.
--
-- The function will abort after <timeout> ms
function smtp_send_email(server, timeout, domain, from, to, data)
        local ret
        local reason
        local tcp = core.tcp()
        local smtp_wait_code = function(tcp, code)
                local ret
                -- Read headers until we reac a 2.. code.
                while true do
                        -- read line
                        ret = tcp:receive("*l")
                        if ret == nil then
                                return false, "Connection unexpectly closed"
                        end
                        -- expected code
                        if string.match(ret, code) ~= nil then
                                return true, nil
                        end
                        -- other code
                        if string.match(ret, '^%d%d%d ') ~= nil then
                                return false, ret
                        end
                        -- other informational message, wait.
                end
        end

	if timeout ~= nil and timeout > 0 then
		tcp:settimeout(timeout / 1000)
	end

        if tcp:connect(server) == nil then
                return false, "Can't connect to \""..server.."\""
        end

        ret, reason = smtp_wait_code(tcp, '^220 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send("HELO " .. domain .. "\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^250 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send("MAIL FROM: <" .. from .. ">\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^250 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send("RCPT TO: <" .. to .. ">\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^250 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send("DATA\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^354 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send(data .. "\r\n.\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^250 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        if tcp:send("QUIT\r\n") == nil then
                tcp:close()
                return false, "Connection unexpectly closed"
        end

        ret, reason = smtp_wait_code(tcp, '^221 ')
        if ret == false then
                tcp:close()
                return false, reason
        end

        tcp:close()
        return true, nil
end

local function send_email_alert(srv, level, event, state, short, message, when)
	local mailers = srv:get_proxy():get_mailers()

	if mailers == nil then
		return -- nothing to do
	end

	if level > mailers.log_level then
		return
	end

	-- email sending is performed asynchronously thanks to mailqueue
	local job = {}

	job.mailconf = mailers
	job.when = when
	job.short = short

	-- in this example, html generation is performed within the event context because html
	-- skeleton is light and this is actually simpler to implement it this way.
	--
	-- but if this "rendering" part were to take too long, it would be recommended to move it
	-- in the mailqueue instead for asynchronous work to make sure events keep being processed
	-- near real-time

	local html_body = core.concat()

	html_body:add("<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\">"..
                      "<style type=\"text/css\">body {text-align: center; font-family: Verdana, sans-serif; font-size: 10pt;}"..
                      "img.logo {float: left; margin: 10px 10px 10px; vertical-align: middle}"..
                      "img.link {float: right;  margin: 0px 1px; vertical-align: middle}"..
                      "span {font-family: Verdana, sans-serif; font-size: 12pt;}"..
                      "table {text-align:center; margin-left: auto; margin-right: auto; border: 1px solid black;}"..
                      "th {white-space: nowrap;}"..
                      "th.even {background-color: #D9D9D9;}"..
                      "td.even {background-color: #F2F2F2;}"..
                      "th.odd {background-color: #F2F2F2;}"..
                      "td.odd {background-color: #FFFFFF;}"..
                      "th,td {font-family: Verdana, sans-serif; font-size: 10pt; text-align:left;}"..
                      "th.customer {width: 600px; background-color: #004488; color: #ffffff;}"..
                      "p.foot {width: 602px; background-color: #004488; color: #ffffff; margin-left: auto; margin-right: auto;}"..
                      "</style></head><body>"..
                      "<table width=\"600px\"><tbody><tr>"..
                      "<td colspan=\"2\"><span>HAProxy event notification system</span></td></tr><tr>"..
                      "<th colspan=\"2\" class=\"customer\">Lua-generated</th></tr><tr>")

	html_body:add(string.format("<th class=\"even\" width=\"180px\">Event type:</th><td class=\"even\">%s</td></tr>", event))
	html_body:add(string.format("<th class=\"odd\" width=\"180px\">Server status:</th><td bgcolor=\"%s\">%s</td></tr>", (state.new_state == "RUNNING" and "#46eb34" or "#eb4034"), (state.new_state == "RUNNING" and "UP" or "DOWN")))
	html_body:add(string.format("<th class=\"even\" width=\"180px\">Server name:</th><td class=\"even\">%s</td></tr>", srv:get_name()))
	local backend_color = "#46eb34"
	if (srv:get_proxy():get_srv_act() == 0) then
		backend_color = "#eb4034"
	end
	html_body:add(string.format("<th class=\"odd\" width=\"180px\">Backend name:</th><td bgcolor=\"%s\">%s</td></tr>", backend_color, srv:get_proxy():get_name()))
	html_body:add(string.format("<th class=\"even\" width=\"180px\">Event time:</th><td class=\"even\">%s</td></tr>", os.date("%a, %d %b %Y %T %z (%Z)", when)))
	html_body:add(string.format("<tr><th class=\"odd\">Full info:</th><td class=\"odd\">%s</td></tr>", message))
	html_body:add("</tbody></table><p class=\"foot\">Generated by HAProxy (From Lua)</p></body></html>")

	job.msg = html_body:dump()

	-- enqueue email job
	mailqueue:push(job)

end

local function srv_get_check_details(check)
	local c = core.concat()

	c:add(", ")
	c:add(string.format("reason: %s", check.reason.desc))
	if check.reason.code ~= nil
	then
		c:add(string.format(", code: %d", check.reason.code))
	end
	if check.duration >= 0
	then
		c:add(string.format(", check duration: %dms", check.duration))
	end

	return c:dump()
end

local function srv_get_status_details(srv, requeued)
	local c = core.concat()

	c:add(string.format("%d active and %d backup servers left.",
			    srv:get_proxy():get_srv_act(),
			    srv:get_proxy():get_srv_bck()))
	c:add(" ")
	c:add(string.format("%d sessions active, %d requeued, %d remaining in queue",
			    srv:get_cur_sess(),
			    requeued,
			    srv:get_pend_conn()))
	return c:dump()
end

local function srv_state_handler(event, data, sub, when)
	local server = data.reference
	local state = data.state
	local c = core.concat()
	local log_level = SYSLOG_LEVEL["ALERT"]
	local email_context

	if server == nil then
		-- server already removed, can't do much
		return
	end

	if state.admin then
		-- don't report if is related to an administrative change and not
		-- directly due to an operational change
		return
	end

	-- we don't send an alert if the server was previously stopping
	if state.old_state == "STOPPING" or server:is_draining() then
		log_level = SYSLOG_LEVEL["NOTICE"]
	end

	-- prepare the message
	c:add(string.format("Server %s/%s is %s",
			    server:get_proxy():get_name(),
			    server:get_name(),
			    state.new_state == "RUNNING" and "UP" or "DOWN"))

	local short = c:dump() -- save short message info

	if server:tracking()
	then
		-- server is tracking another server, it means that the operational
		-- state change is inherited
		c:add(string.format(" via %s/%s",
				    server:tracking():get_proxy():get_name(),
				    server:tracking():get_name()))
	end

	if state.check ~= nil
	then
		c:add(srv_get_check_details(state.check))
	else
		c:add(state.cause)
	end

	c:add(". ")
	c:add(srv_get_status_details(server, state.requeued))
	send_email_alert(server, log_level, event, state, short, c:dump(), when)
end

-- single function for multiple event types since all events come
-- from the same subscription to reduce memory footprint
local function srv_event_dispatch(event, data, mgmt, when)
	if event == "SERVER_STATE" then srv_state_handler(event, data, when) end
end

local function mailers_track_server_events(srv)
	local mailer_conf = srv:get_proxy():get_mailers()

	-- don't track server events if the parent proxy did not enable email alerts
	if mailer_conf == nil
	then return
	end

	-- perform the event subscription from the server
	srv:event_sub({"SERVER_STATE"}, srv_state_handler)
end

local function srv_event_add(event, data)
	-- do nothing if the server was already removed
	if data.reference == nil
	then return
	end

	-- server still exists, check if it can be tracked for email alerts
	mailers_track_server_events(data.reference)
end


-- disable legacy email-alerts since email-alerts will be sent from lua directly
core.disable_legacy_mailers()

-- event subscriptions are purposely performed in an init function to prevent
-- email alerts from being generated too early (when process is starting up)
core.register_init(function()

	-- do nothing if not on primary thread
	-- this prevents emails from being sent multiple times when
	-- lua-load-per-thread is used to load the script since the task
	-- will be started on each haproxy thread
	if core.thread > 1 then core.done() end

	-- subscribe to SERVER_ADD to be notified when new servers are added
	core.event_sub({"SERVER_ADD"}, srv_event_add)

	-- loop through existing backends to detect existing servers
	for backend_name, backend in pairs(core.backends) do
		for srv_name, srv in pairs(backend.servers) do
			mailers_track_server_events(srv)
		end
	end

end)

-- mail queue
core.register_task(function()
	while true
	do
		local job = mailqueue:pop_wait()

		if job ~= nil then
			local date = os.date("%a, %d %b %Y %T %z (%Z)", job.when)
			local c = core.concat()

			-- prepare email body
			c:add(string.format("From: %s\r\n", job.mailconf.smtp_from))
			c:add(string.format("To: %s\r\n", job.mailconf.smtp_to))
			c:add(string.format("Date: %s\r\n", date))
			c:add(string.format("Subject: [HAProxy Alert] %s\r\n", job.short))
			c:add("Content-Type: text/html; charset=\"utf-8\"\r\n")
			c:add("Content-Transfer-Encoding: quoted-printable\r\n")
			c:add("\r\n")
			c:add(string.format("%s\r\n", job.msg))

			-- send email to all mailservers
			for name, mailsrv in pairs(job.mailconf.mailservers) do
				-- finally, send email to server
				local ret, reason = smtp_send_email(mailsrv,
								    job.mailconf.mailservers_timeout,
								    job.mailconf.smtp_hostname,
								    job.mailconf.smtp_from,
								    job.mailconf.smtp_to,
								    c:dump())
				if ret == false then
					core.Warning("Can't send email alert to ".. name .. ": " .. reason)
				end
			end
		end
	end
end)
