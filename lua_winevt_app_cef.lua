local parserName = "lua_winevt_app_cef"
local parserVersion = "2018.04.20.6"

local lua_winevt_app_cef = nw.createParser(parserName, "Protobuf raw parsing example")

nw.logDebug(parserName .. " " .. parserVersion)
--[[

]]--

function lua_winevt_app_cef:sessionBegin()

	launchArgFlag = nil
	launchArgs = nil
	
end

function lua_winevt_app_cef:flagCheck(index,launchArgs)
	-- --nw.logInfo(parserName .. ": flagCheck(index,launchArgs)" .. launchArgs)

	-- do we have the flag we are looking for to do other work with
	-- check for event.source to match SWIFT
	if launchArgs == "SWIFT" then
		-- flag found continue with detection content
		launchArgFlag = 1
		
		-- print out debug info for log scraping
		-- --nw.logInfo(parserName .. ": flagCheck true")
		-- --nw.logInfo(parserName .. ": launchArgs: " .. launchArgs)
		--nw.logInfo(parserName .. ": " .. raw)
		-- 
	end	
	
end


--[[
%NICWIN-4-Application_1_SWIFT: Application,rn=30861 cid=0 eid=1,Mon Jul 30 17:53:39 2018,1,SWIFT,,Information,JUST.A.FDQN,No category file,,No description string found. string-data=[CEF:0|SWIFT|Alliance Access|7.2.0|BSA-3001|Signoff|Low|cn1=2147483450 cn1Label=Event Sequence ID cs1=13782e0f-bf93-4033-831a-86f46ec0159b cs1Label=Instance UUID cs2=54f5a672-a658-491b-89b5-59463d51e7b2 cs2Label=Correlation ID cat=Operator msg=Operator PARTNER : signed off from the terminal '172.34.34.34'. suid=PARTNER dvchost=SRVSWIFTAA-TEST dvc=172.33.33.33 dvcmac=00:FF:56:A0:86:BB deviceProcessName=WS_appsrv src=172.34.34.34 dtz=America/Buenos_Aires rt=1532973219000 ]

token match on
string-data=[

end on
]

--]]
function lua_winevt_app_cef:onSessionEnd()
    -- --nw.logInfo(parserName .. ": onSessionEnd()")

	-- only execute if flag set
	if launchArgFlag then
		-- get the one packet
		local packet = nwsession.getFirstPacket()

		-- its payload *is* the raw
		local payload = nwpacket.getPayload(packet)

		-- we can get it as a Lua string...
		local raw = nwpayload.tostring(payload)
		-- --nw.logInfo(parserName .. ": raw:  " .. raw)
		
		-- if this is a flag set then raw parse the payload
		-- look for the start and end position of the anchor
		local i,valfind = string.find(raw, "string-data=[")
		if valfind then
			nw.logInfo(parserName .. ": found the token in raw .. attempting to find position: " .. valfind)
			-- find the ending tag for the string
			local valend = string.find(raw, "]", valfind, -1)
			if valfind then
				--local valpol = string.sub(raw, valfind + 1, valend - 1)
				local valpol = string.sub(raw, valfind, valend - 1)
				if valpol then
					-- we have the cef string in the win event
					--nw.createMeta(self.keys["policy.name"], valpol)
					nw.logInfo(parserName .. ": args: " .. valpol)
					nw.logInfo(parserName .. ": args length: " .. string.len(valpol))
				end
			end
		end

		--nw.logDebug(raw)
	end
end

lua_winevt_app_cef:setCallbacks({
	[nwevents.OnSessionBegin] = lua_winevt_app_cef.sessionBegin,
	-- check for param or param.src keys existing
    -- [nwlanguagekey.create("nwe.callback_id", nwtypes.Text)] = lua_winevt_app_cef.flagCheck,
	-- this is the metakey to key on (event.source="SWIFT"
	[nwlanguagekey.create("event.source", nwtypes.Text)] = lua_winevt_app_cef.flagCheck,
	[nwevents.OnSessionEnd] = lua_winevt_app_cef.onSessionEnd,
    -- needed to ensure end event callback is registered, some sort of check to
    -- determen if raw contains values that require parsing would be made here
    
})
