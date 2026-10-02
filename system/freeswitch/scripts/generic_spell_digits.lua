-- File: /usr/share/freeswitch/scripts/generic_spell_digits.lua
-- A generic script to spell out a number using audio files from a specified folder.

-- Arguments are passed in the 'argv' table.
-- argv[1] should be the number to spell.
-- argv[2] should be the path to the audio folder.
local number_to_spell = argv[1]
local audio_folder_path = argv[2]

freeswitch.consoleLog("info", "--- Running generic_spell_digits.lua ---")

-- --- Input Validation ---
if not number_to_spell or not audio_folder_path then
    freeswitch.consoleLog("crit", "Script called with missing arguments. Required: <number> <folder_path>\n")
    return
end

-- Ensure the audio folder path ends with a slash for clean concatenation
if not audio_folder_path:match("/$") then
    audio_folder_path = audio_folder_path .. "/"
end

freeswitch.consoleLog("info", "Number to spell: " .. number_to_spell)
freeswitch.consoleLog("info", "Audio folder path: " .. audio_folder_path)

-- --- Main Logic ---
-- Answer the call if it hasn't been already
if not session:answered() then
    session:answer()
end

if session:ready() then
    -- Loop through each character (digit) of the number string
    for i = 1, #number_to_spell do
        local digit = number_to_spell:sub(i, i)
        local file_to_play = audio_folder_path .. digit .. ".wav"

        freeswitch.consoleLog("info", "Playing digit '" .. digit .. "' from file: " .. file_to_play)

        -- streamFile is efficient for playing files inside a script
        session:streamFile(file_to_play)

        -- If the caller hangs up during playback, stop the script
        if not session:ready() then
            freeswitch.consoleLog("notice", "Caller disconnected during playback. Exiting loop.\n")
            break
        end
    end
else
    freeswitch.consoleLog("warning", "Session is not ready. Cannot play audio.\n")
end

freeswitch.consoleLog("info", "--- Finished generic_spell_digits.lua ---\n")
