freeswitch.consoleLog("info", "In IVR LUA\n")

-- Get the destination number
dest_num = session:getVariable("destination_number_ori");

freeswitch.consoleLog("info", "Destination Number: " .. tostring(dest_num) .. "\n")
-- Answer the call (ensures media can be played)
session:answer()

-- Check if session is still active
if session:ready() then
    freeswitch.consoleLog("info", "Playing number: " .. dest_num .. "\n")

    -- Loop through each digit and play the corresponding file
    for i = 1, #dest_num do
        digit = dest_num:sub(i, i) -- Extract each digit
        file_path = "/opt/mal_vm_04/" .. digit .. ".wav"
        
        -- Log the file being played
        freeswitch.consoleLog("info", "Playing file: " .. file_path .. "\n")
        
        -- Play the file
        session:streamFile(file_path)

        -- Check if session is still active after playing each file
        if not session:ready() then
            freeswitch.consoleLog("info", "Call disconnected while playing\n")
            break
        end
    end
else
    freeswitch.consoleLog("err", "Call session not ready. Exiting script.\n")
end
