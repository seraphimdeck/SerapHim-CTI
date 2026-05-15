import "pe"
import "math"

rule APT_PRC_SparrowDoor_Comprehensive_CTI003 {
    meta:
        author = "SerapHim"
        description = "Detects SparrowDoor Stage 1 Loader combining ESET IOCs and SerapHim's original [PHIM] behavioral findings"
        report_id = "CTI-003 SparrowDoor"
        date = "2026-03-16"
        sample_source_eset_hash = "8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4"

    strings:
        $eset_export_k7ui_1 = "K7UI_1" ascii
        $eset_export_k7ui_13 = "K7UI_13" ascii
        
        $seraphim_variant_stage2_ref = "MpSvc.dll" ascii
        
        $seraphim_phim_substitution_table_1 = "!\"#$%&'()*+,-" ascii
        $seraphim_phim_substitution_table_2 = "abcdefghijklmnopqrstuvwxyz [\\]^_ abcdefghijklmnopqrstuvwxyz |}~" ascii
        
        $seraphim_phim_indirect_call_opcode = { FF 15 }
        
        $seraphim_phim_inverted_antisandbox_exc = { 09 04 00 C0 }
        $seraphim_phim_inverted_antisandbox_cookie1 = { 4E E6 40 BB }
        $seraphim_phim_inverted_antisandbox_cookie2 = { B1 19 BF 44 }

    condition:
        uint16(0) == 0x5A4D and 
        filesize < 50KB and 
        all of ($eset_*, $seraphim_variant_*, $seraphim_phim_substitution_table_*, $seraphim_phim_inverted_antisandbox_*) and 
        #seraphim_phim_indirect_call_opcode > 100 and 
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".text" and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 6.5
        )
}
