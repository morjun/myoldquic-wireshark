do
    local p_quic = Proto ("quic_d9c", "Quic proto version draft 9 custom")

    local f = p_quic.fields

    f.f_quic_flags = ProtoField.uint8 ("quic.flags","QUIC Flags")
    f.f_quic_short = ProtoField.uint8 ("quic.short","QUIC Short Header")
    f.f_quic_long = ProtoField.uint8 ("quic.long","QUIC Long Header")

    f.f_quic_packetType = ProtoField.string ("quic.packetType","QUIC Packet Type")

    f.f_quic_hasConnectionId = ProtoField.bool("quic.hasConnectionId","QUIC Connection ID Existence")
    f.f_quic_keyPhase = ProtoField.bool("quic.keyPhase","QUIC Key Phase")


    f.f_quic_DCI = ProtoField.uint64("quic.DCI","Dst Connection ID")

    f.f_quic_version = ProtoField.uint32 ("quic.version","QUIC Version")

    f.f_quic_packetNumber = ProtoField.uint32 ("quic.packetNumber","QUIC Packet Number")
    -- f.f_quic_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len", base.DEC, nil, 0xf0)
    -- f.f_quic_real_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len after cal")
    -- f.f_quic_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len", base.DEC, nil, 0x0f)
    -- f.f_quic_real_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len after cal")
    -- f.f_quic_SCI = ProtoField.bytes("quic.SCI","Src Connection ID")

    function p_quic.dissector(tvb, pinfo, tree)
        pinfo.cols.protocol = "QUIC/DRAFT-9-CUSTOM"
        local subtree = tree:add (p_quic, tvb()) -- tvb: packet's buffer
        local offset = 0

        local first_oct = tvb(offset, 1) -- 1 byte field
        offset = offset + 1
        subtree:add (f.f_quic_flags, first_oct)

        local headerType = tvb.bitfield()

        if headerType == 0x01 then
            f.f_quic_packetType = ProtoField.uint8 ("quic.packetType","QUIC Packet Type", base.DEC, nil, 0xef)

            local longTree = subtree:add (f.f_quic_long, headerType)
            local packetType = tvb.bitfield(1,7)
            longTree:add (f.f_quic_packetType, packetType)

            if packetType == 0x7f then
                longTree:add (f.f_quic_packetType, "Initial")
            elseif packetType == 0x7e then
                longTree:add (f.f_quic_packetType, "Retry")
            elseif packetType == 0x7d then
                longTree:add (f.f_quic_packetType, "Handshake")
            elseif packetType == 0x7c then
                longTree:add (f.f_quic_packetType, "0-RTT")
            end

        elseif headerType == 0x00 then
            f.f_quic_packetType = ProtoField.uint8 ("quic.packetType","QUIC Packet Type", base.DEC, nil, 0x0f)
            local shortTree = subtree:add (f.f_quic_short, headerType)

            local hasConnectionId = tvb.bitfield(1,1)
            local keyPhase = tvb.bitfield(2,1)
            local spin = tvb.bitfield(3,1)
            local packetType = tvb.bitfield(4,4)

            shortTree:add (f.f_quic_hasConnectionId, hasConnectionId)
            shortTree:add (f.f_quic_keyPhase, keyPhase)
            shortTree:add (f.f_quic_spin, spin)
            shortTree:add (f.f_quic_packetType, packetType)

        end

        local dci = tvb(offset, 8)
        offset = offset + 8
        subtree:add (f.f_quic_DCI, dci)

        if headerType == 0x01 then
            local version = tvb(offset, 4)
            offset = offset + 4
            longTree:add (f.f_quic_version, version)

        end

        if headerType == 0x00 then
            local pacektNumber = tvb(offset, packetType)
            offset = offset + packetType
        else then
            local packetNumber = tvb(offset, 4)
            offset = offset + 4
        end
        subtree:add (f.f_quic_packetNumber, packetNumber)

    end

    -- Register the dissector
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(49153,p_quic)
end
