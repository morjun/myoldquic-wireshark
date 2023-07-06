do
    local p_quic = Proto ("quic_ns3", "Quic proto ns3 custom version")

    local f = p_quic.fields

    f.f_quic_flags = ProtoField.uint8 ("quic.flags","QUIC Flags")

    f.f_quic_packetTypeString = ProtoField.string ("quic.packetTypeString","QUIC Packet Type String")

    f.f_quic_hasConnectionId = ProtoField.bool("quic.hasConnectionId","QUIC Connection ID Existence")
    f.f_quic_keyPhase = ProtoField.bool("quic.keyPhase","QUIC Key Phase")
    f.f_quic_spin = ProtoField.bool("quic.spin","QUIC Spin Bit")


    f.f_quic_DCI = ProtoField.uint64("quic.DCI","Dst Connection ID")

    f.f_quic_version = ProtoField.uint32 ("quic.version","QUIC Version")

    f.f_quic_packetNumber = ProtoField.uint32 ("quic.packetNumber","QUIC Packet Number")
    -- f.f_quic_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len", base.DEC, nil, 0xf0)
    -- f.f_quic_real_DCIL = ProtoField.uint8 ("quic.DCIL","Dst Connection ID Len after cal")
    -- f.f_quic_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len", base.DEC, nil, 0x0f)
    -- f.f_quic_real_SCIL = ProtoField.uint8 ("quic.SCIL","Src Connection ID Len after cal")
    -- f.f_quic_SCI = ProtoField.bytes("quic.SCI","Src Connection ID")

    function p_quic.dissector(tvb, pinfo, tree)
        pinfo.cols.protocol = "QUIC/NS3"
        local subtree = tree:add (p_quic, tvb()) -- tvb: packet's buffer
        local offset = 0
        local packetType = 0
        local packetNumber = 0

        local first_oct = tvb(offset, 1) -- 1 byte field
        offset = offset + 1
        subtree:add (f.f_quic_flags, first_oct)

        local headerType = first_oct:bitfield(0,1)

        if headerType == 0x01 then
            f.f_quic_packetType = ProtoField.uint8 ("quic.packetType","QUIC Packet Type", base.DEC, nil, 0xef)

            local packetType = first_oct:bitfield(1,7)
            subtree:add (f.f_quic_packetType, packetType)

            if packetType == 0 then
                subtree:add (f.f_quic_packetTypeString, "Versio Negotiation")
            elseif packetType == 1 then
                subtree:add (f.f_quic_packetTypeString, "Initial")
            elseif packetType == 2 then
                subtree:add (f.f_quic_packetTypeString, "Retry")
            elseif packetType == 3 then
                subtree:add (f.f_quic_packetTypeString, "Handshake")
            elseif packetType == 4 then
                subtree:add (f.f_quic_packetTypeString, "0-RTT")
            end

        elseif headerType == 0x00 then
            f.f_quic_packetType = ProtoField.uint8 ("quic.packetType","QUIC Packet Type", base.DEC, nil, 0x0f)

            local hasConnectionId = first_oct:bitfield(1,1)
            local keyPhase = first_oct:bitfield(2,1)
            local spin = first_oct:bitfield(3,1)
            packetType = first_oct:bitfield(4,4)

            subtree:add (f.f_quic_hasConnectionId, hasConnectionId)
            subtree:add (f.f_quic_keyPhase, keyPhase)
            subtree:add (f.f_quic_spin, spin)
            subtree:add (f.f_quic_packetType, packetType)

        end

        local dci = tvb(offset, 8)
        offset = offset + 8
        subtree:add (f.f_quic_DCI, dci)

        if headerType == 0x01 then
            local version = tvb(offset, 4)
            offset = offset + 4
            subtree:add (f.f_quic_version, version)

        end

        if headerType == 0x00 then
            packetNumber = tvb(offset, packetType)
            offset = offset + packetType
        else
            packetNumber = tvb(offset, 4)
            offset = offset + 4
        end
        subtree:add (f.f_quic_packetNumber, packetNumber)

    end

    -- Register the dissector
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(49153,p_quic)
end
