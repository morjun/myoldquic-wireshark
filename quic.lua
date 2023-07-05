do
    local p_quic = Proto ("quic_d9c", "Quic proto version draft 9 custom")

    local f = p_quic.fields

    f.f_quic_flags = ProtoField.uint8 ("quic.flags","QUIC Flags")
    f.f_quic_short = ProtoField.uint8 ("quic.short","QUIC Short Header")
    f.f_quic_long = ProtoField.uint8 ("quic.long","QUIC Long Header")

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

        -- TODO: flag 파싱 -> tvb.bitfiled 활용할 것

        local dci = tvb(offset, 8)
        offset = offset + 8
        subtree:add (f.f_quic_DCI, dci)

        -- TODO: Long Header일 때만 Version 필드 추가

        local version = tvb(offset, 4)
        offset = offset + 4
        subtree:add (f.f_quic_version, version)

        -- TODO: Short Header인지 검사하고, Short일 경우 가변 길이 패킷 번호 구현

        local packetNumber = tvb(offset, 4)
        offset = offset + 4
        subtree:add (f.f_quic_packetNumber, packetNumber)

    end

    -- Register the dissector
    local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(49153,p_quic)
end
