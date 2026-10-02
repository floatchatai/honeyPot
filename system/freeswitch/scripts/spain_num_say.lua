freeswitch.consoleLog("info", "In IVR LUA\n")

-- Get the destination number
dest_num = session:getVariable("destination_number_ori");

if dest_num then
    freeswitch.consoleLog("info", "Playing number: " .. dest_num .. "\n")

    -- Loop through each digit and play the corresponding file
    for i = 1, #dest_num do
        digit = dest_num:sub(i, i) -- Extract each digit
        file_path = "/opt/spain_num_say" .. digit .. ".wav"
        
        -- Log the file being played
        freeswitch.consoleLog("info", "Playing file: " .. file_path .. "\n")
        
        -- Play the file
        session:streamFile(file_path)
    end
else
    freeswitch.consoleLog("err", "No destination number found\n")
end

