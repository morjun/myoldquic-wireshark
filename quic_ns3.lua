local function readVarInt64(tvb, offset)
    local firstOct = tvb(offset, 1)

    offset = offset + 1
    local size = 1
    local mask = firstOct:bitfield(0, 2)
    if (mask == 0x0) then
        size = 1
    elseif (mask == 0x1) then
        size = 2
    elseif (mask == 0x2) then
        size = 4
    elseif (mask == 0x3) then
        size = 8
    end
    local valueField = tvb(offset - 1, size)
    local value = firstOct:uint64() - bit.lshift(mask, 6) --UInt64 Object

    if (size > 1) then
        value = tvb(offset, size - 1):uint64() + bit.lshift(value:tonumber(), (size - 1) * 8)
    end

    offset = offset + (size - 1)
    return valueField, value, size
end


do
    local p_quic = Proto("quic_ns3", "Quic proto ns3 custom version")

    local f = p_quic.fields

    local packetTypes = {
        [0] = "Version Negotiation",
        [1] = "Initial",
        [2] = "Retry",
        [3] = "Handshake",
        [4] = "0-RTT"
    }

    local frameTypes = {
        [0x00] = "PADDING",           --!< Padding
        [0x01] = "RST_STREAM",        --!< Rst Stream
        [0x02] = "CONNECTION_CLOSE",  --!< Connection Close
        [0x03] = "APPLICATION_CLOSE", --!< Application Close
        [0x04] = "MAX_DATA",          --!< Max Data
        [0x05] = "MAX_STREAM_DATA",   --!< Max Stream Data
        [0x06] = "MAX_STREAM_ID",     --!< Max Stream Id
        [0x07] = "PING",              --!< Ping
        [0x08] = "BLOCKED",           --!< Blocked
        [0x09] = "STREAM_BLOCKED",    --!< Stream Blocked
        [0x0A] = "STREAM_ID_BLOCKED", --!< Stream Id Blocked
        [0x0B] = "NEW_CONNECTION_ID", --!< New Connection Id
        [0x0C] = "STOP_SENDING",      --!< Stop Sending
        [0x0D] = "ACK",               --!< Ack
        [0x0E] = "PATH_CHALLENGE",    --!< Path Challenge
        [0x0F] = "PATH_RESPONSE",     --!< Path Response
        [0x10] = "STREAM000",         --!< Stream (offset=0, length=0, fin=0)
        [0x11] = "STREAM001",         --!< Stream (offset=0, length=0, fin=1)
        [0x12] = "STREAM010",         --!< Stream (offset=0, length=1, fin=0)
        [0x13] = "STREAM011",         --!< Stream (offset=0, length=1, fin=1)
        [0x14] = "STREAM100",         --!< Stream (offset=1, length=0, fin=0)
        [0x15] = "STREAM101",         --!< Stream (offset=1, length=0, fin=1)
        [0x16] = "STREAM110",         --!< Stream (offset=1, length=1, fin=0)
        [0x17] = "STREAM111",         --!< Stream (offset=1, length=1, fin=1)
    }

    local errorCodes = {
        [0x00] = "NO_ERROR",                  -- No error
        [0x01] = "INTERNAL_ERROR",            -- Implementation error
        [0x02] = "SERVER_BUSY",               -- Server currently busy
        [0x03] = "FLOW_CONTROL_ERROR",        -- Flow control error
        [0x04] = "STREAM_ID_ERROR",           -- Invalid stream ID
        [0x05] = "STREAM_STATE_ERROR",        -- Frame received in invalid stream state
        [0x06] = "FINAL_OFFSET_ERROR",        -- Change to final stream offset
        [0x07] = "FRAME_FORMAT_ERROR",        -- Generic frame format error
        [0x08] = "TRANSPORT_PARAMETER_ERROR", -- Error in transport parameters
        [0x09] = "VERSION_NEGOTIATION_ERROR", -- Version negotiation failure
        [0x0A] = "PROTOCOL_VIOLATION",        -- Generic protocol violation
        [0x0B] = "UNSOLICITED_PATH_ERROR",    -- Unsolicited PATH_RESPONSE frame
        [0x10] = "FRAME_ERROR",               -- Specific frame format error [0x100-0x1FF] -> will simply use Frame Error 0x100 as a mask and summing specific TypeFrame_t
    }


    f.f_quic_flags = ProtoField.uint8("quic.flags", "QUIC Flags", base.HEX, nil)

    f.f_quic_packetType = ProtoField.uint8("quic.packetType", "QUIC Packet Type", base.DEC, packetTypes, 0x7f)

    f.f_quic_hasConnectionId = ProtoField.bool("quic.hasConnectionId", "QUIC Connection ID Existence")
    f.f_quic_keyPhase = ProtoField.bool("quic.keyPhase", "QUIC Key Phase")
    f.f_quic_spin = ProtoField.bool("quic.spin", "QUIC Spin Bit")

    f.f_quic_longHeader = ProtoField.none("quic.longHeader", "QUIC Long Header")
    f.f_quic_shortHeader = ProtoField.none("quic.shortHeader", "QUIC Short Header")

    f.f_quic_DCI = ProtoField.uint64("quic.DCI", "Dst Connection ID")

    f.f_quic_version = ProtoField.uint32("quic.version", "QUIC Version")
    f.f_quic_supportedVersions = ProtoField.none("quic.supportedVersions", "QUIC Supported Versions")
    f.f_quic_supportedVersion = ProtoField.uint32("quic.supportedVersion", "QUIC Supported Version")

    f.f_quic_packetNumber = ProtoField.uint32("quic.packetNumber", "QUIC Packet Number")
    -- f.f_quic_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len", base.DEC, nil, 0xf0)
    -- f.f_quic_real_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len after cal")
    -- f.f_quic_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len", base.DEC, nil, 0x0f)
    -- f.f_quic_real_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len after cal")
    -- f.f_quic_SCI = ProtoField.bytes("quic.SCI","Src Connection ID")

    f.f_quic_frameType = ProtoField.uint8("quic.frameType", "QUIC Frame Type", base.HEX, frameTypes)

    f.f_quic_streamId = ProtoField.uint64("quic.streamId", "QUIC Stream ID")
    f.f_quic_errorCode = ProtoField.uint16("quic.errorCode", "QUIC Transport Error Code", base.HEX, errorCodes)
    f.f_quic_streamOffset = ProtoField.uint64("quic.streamOffset", "QUIC Stream Offset")
    f.f_quic_reasonPhrase = ProtoField.string("quic.reasonPhrase", "QUIC Reason Phrase")
    f.f_quic_maxData = ProtoField.uint64("quic.maxData", "QUIC Max Data")

    f.f_quic_largestAcked = ProtoField.uint64("quic.largestAcked", "QUIC Largest Acked")
    f.f_quic_ackDelay = ProtoField.uint64("quic.ackDelay", "QUIC Ack Delay")
    f.f_quic_ackBlockCount = ProtoField.uint64("quic.ackBlockCount", "QUIC Ack Block Count")
    f.f_quic_ackBlock = ProtoField.uint64("quic.ackBlock", "QUIC Ack Block")
    f.f_quic_ackBlockGap = ProtoField.uint64("quic.ackBlockGap", "QUIC Ack Block Gap")
    f.f_quic_firstAckBlock = ProtoField.uint64("quic.firstAckBlock", "QUIC First Ack Block")

    f.f_quic_streamLength = ProtoField.uint64("quic.streamLength", "QUIC Stream Length")
    f.f_quic_stream = ProtoField.string("quic.stream", "QUIC Stream Bytes")


    function p_quic.dissector(tvb, pinfo, tree)
        pinfo.cols.protocol = "QUIC/NS3"
        local subtree = tree:add(p_quic, tvb()) -- tvb: packet's buffer, 기본 길이: 남은 바이트 수
        local offset = 0
        local packetType = 0
        local packetNumber = 0

        local first_oct = tvb(offset, 1) -- 1 byte field
        offset = offset + 1

        local headerType = first_oct:bitfield(0, 1)
        local longHeader
        local shortHeader

        if headerType == 0x01 then
            longHeader = subtree:add(f.f_quic_longHeader)
            local flags = longHeader:add(f.f_quic_flags, first_oct)
            packetType = first_oct:bitfield(1, 7)
            flags:add(f.f_quic_packetType, packetType)
        elseif headerType == 0x00 then
            shortHeader = subtree:add(f.f_quic_shortHeader)
            local flags = shortHeader:add(f.f_quic_flags, first_oct)
            local hasConnectionId = first_oct:bitfield(1, 1)
            local keyPhase = first_oct:bitfield(2, 1)
            local spin = first_oct:bitfield(3, 1)
            packetType = first_oct:bitfield(4, 4)

            flags:add(f.f_quic_hasConnectionId, hasConnectionId)
            flags:add(f.f_quic_keyPhase, keyPhase)
            flags:add(f.f_quic_spin, spin)
        end

        local dci = tvb(offset, 8)
        offset = offset + 8
        subtree:add(f.f_quic_DCI, dci)

        if headerType == 0x01 then
            local version = tvb(offset, 4)
            offset = offset + 4
            longHeader:add(f.f_quic_version, version)
        end

        if headerType == 0x00 then
            packetNumber = tvb(offset, bit.lshift(1, packetType))
            offset = offset + bit.lshift(1, packetType)
        else
            if packetType ~= 0x00 then
                packetNumber = tvb(offset, 4)
                offset = offset + 4
            end
        end
        subtree:add(f.f_quic_packetNumber, packetNumber)

        if packetType == 0x00 and headerType == 0x01 then
            local supportedVersions = longHeader:add(f.f_quic_supportedVersions)
            while offset < tvb:len() do
                local supportedVersion = tvb(offset, 4)
                offset = offset + 4
                supportedVersions:add(f.f_quic_supportedVersion, supportedVersion)
            end
        else
            while offset < tvb:len() do
                local frameType = tvb(offset, 1)
                offset = offset + 1

                local frame = subtree:add(f.f_quic_frameType, frameType)

                frameType = frameType:uint()

                if frameType == 0x01 then
                    local streamIdBuf, streamId, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamId, streamIdBuf, streamId)

                    local errorCode = tvb(offset, 2)
                    offset = offset + 2
                    frame:add(f.f_quic_errorCode, errorCode)

                    local streamOffsetBuf, streamOffset, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamOffset, streamOffsetBuf, streamOffset)
                elseif frameType == 0x02 or frameType == 0x03 then
                    local errorCode = tvb(offset, 2)
                    offset = offset + 2
                    frame:add(f.f_quic_errorCode, errorCode)

                    local reasonPhraseLengthBuf, reasonPhraseLength, size = readVarInt64(tvb, offset)
                    offset = offset + size

                    local reasonPhrase = tvb(offset, reasonPhraseLength:tonumber())
                    offset = offset + reasonPhraseLength:tonumber()

                    frame:add(f.f_quic_reasonPhrase, reasonPhrase)
                elseif frameType == 0x04 then
                    local maxDataBuf, maxData, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_maxData, maxDataBuf, maxData)
                elseif frameType == 0x0d then
                    local largestAckedBuf, largestAcked, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_largestAcked, largestAckedBuf, largestAcked)

                    local ackDelayBuf, ackDelay, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_ackDelay, ackDelayBuf, ackDelay)

                    local ackBlockCountBuf, ackBlockCount, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    local ackBlocks = frame:add(f.f_quic_ackBlockCount, ackBlockCountBuf, ackBlockCount)

                    local firstAckBlockBuf, firstAckBlock, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    ackBlocks:add(f.f_quic_firstAckBlock, firstAckBlockBuf, firstAckBlock)

                    for i = 0, ackBlockCount:tonumber() - 1 do
                        local gapBuf, gap, size = readVarInt64(tvb, offset)
                        offset = offset + size
                        ackBlocks:add(f.f_quic_ackBlockGap, gapBuf, gap)

                        local ackBlockBuf, ackBlock, size = readVarInt64(tvb, offset)
                        offset = offset + size
                        ackBlocks:add(f.f_quic_ackBlock, ackBlockBuf, ackBlock)
                    end
                elseif frameType == 0x12 then
                    local streamIdBuf, streamId, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamId, streamIdBuf, streamId)

                    local lengthBuf, length, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamLength, lengthBuf, length)

                    local stream = tvb(offset, length:tonumber())
                    offset = offset + length:tonumber()
                    frame:add(f.f_quic_stream, stream)
                elseif frameType == 0x16 then
                    local streamIdBuf, streamId, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamId, streamIdBuf, streamId)

                    local streamOffsetBuf, streamOffset, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamOffset, streamOffsetBuf, streamOffset)

                    local lengthBuf, length, size = readVarInt64(tvb, offset)
                    offset = offset + size
                    frame:add(f.f_quic_streamLength, lengthBuf, length)

                    local stream = tvb(offset, length:tonumber())
                    offset = offset + length:tonumber()
                    frame:add(f.f_quic_stream, stream)
                end
            end
        end
    end

    -- Register the dissector
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(49153, p_quic)
end
