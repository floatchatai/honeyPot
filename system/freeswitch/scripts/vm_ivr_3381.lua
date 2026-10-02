freeswitch.consoleLog("info", "In IVR LUA")

-- Example usage: Play the number '1234567890'
destination_number = session:getVariable("destination_number_ori")
session:answer()
freeswitch.consoleLog("INFO", "Destination Number: " .. tostring(destination_number))

-- Function to play a number
function play_number(destination_number)
    freeswitch.consoleLog("INFO", "IN FUNCTION")

    -- Check if the destination_number is valid (only digits 0-9)
    if destination_number:match("^[0-9]+$") then
        -- Play the start audio
        session:execute("playback", "/usr/local/freeswitch/sounds/italy_3381/italy_Start.wav")

        -- Loop through each digit in the destination number and play the corresponding audio file
        for i = 1, #destination_number do
            local digit = destination_number:sub(i, i)  -- Extract the digit (as a string)
            local audio_file = "/usr/local/freeswitch/sounds/italy_3381/" .. digit .. ".wav"  -- Path to the recorded number file

            -- Check if the audio file exists
            local file = io.open(audio_file, "r")
            if file then
                file:close()
                -- Play the audio file for the digit
                session:execute("playback", audio_file)
                freeswitch.consoleLog("INFO", "Played number: " .. digit)
            else
                freeswitch.consoleLog("ERR", "Audio file not found for number: " .. digit)
            end
        end

        -- Play the end audio
        session:execute("playback", "/usr/local/freeswitch/sounds/italy_3381/italy_End.wav")
        freeswitch.consoleLog("INFO", "END PLAYINGGGG .... ")

        -- Sleep for 3 seconds (pause before deciding to play again)
        session:execute("sleep", "180000")

        -- Check if the session is still active before calling play_number again
        if session:ready() then
            freeswitch.consoleLog("INFO", "Re-executing play_number function again...")
            -- After 3 seconds, re-execute the same function if the session is still active
            play_number(destination_number)
        else
            freeswitch.consoleLog("INFO", "Call has been hung up or is not active. Stopping.")
        end
    else
        freeswitch.consoleLog("ERR", "Invalid destination number: " .. destination_number)
    end
end

-- Check if the session is ready
if session:ready() then
    -- Play the destination number
    play_number(destination_number)
    freeswitch.consoleLog("INFO", "EXECUTE FUNCTION")
else
    freeswitch.consoleLog("ERR", "Session is not ready.")
end
