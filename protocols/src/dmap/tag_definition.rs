use phf::phf_map;
use Tag::*;

pub(crate) enum Tag {
    Uint,
    Str,
    Dict,
    Data,
    Bool,
}

// https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/tag_definitions.py
pub(crate) static DMAP_MAP: phf::Map<&'static str, Tag> = phf_map! {
    // com.apple.itunes.like-button
    "aelb"=>Uint,
    // com.apple.itunes.liked-state
    "aels"=>Uint,
    // com.apple.itunes.req-fplay
    "aeFP"=>Uint,
    // com.apple.itunes.can-be-genius-seed
    "aeGs"=>Uint,
    // com.apple.itunes.music-sharing-version
    "aeSV"=>Uint,
    // daap.protocolversion
    "apro"=>Uint,
    // daap.songalbumid
    "asai"=>Uint,
    // daap.songalbum
    "asal"=>Str,
    // daap.songartist
    "asar"=>Str,
    // com.apple.itunes.gapless-resy
    "asgr"=>Uint,
    // daap.songtime
    "astm"=>Uint,
    // daap.supportsextradata
    "ated"=>Uint,
    // dacp.albumrepeat
    "caar"=>Uint,
    // dacp.albumshuffle
    "caas"=>Uint,
    // dacp.controlint
    "caci"=>Dict,
    // dacp.fullscreenenabled
    "cafe"=>Uint,
    // dacp.fullscreen
    "cafs"=>Uint,
    // daap.nowplayingartist
    "cana"=>Str,
    // dacp.nowplayinggenre
    "cang"=>Str,
    // daap.nowplayingalbum
    "canl"=>Str,
    // daap.nowplayingtrack
    "cann"=>Str,
    // daap.nowplayingid
    "canp"=>Uint,
    // dacp.remainingtime
    "cant"=>Uint,
    // dacp.protocolversion
    "capr"=>Uint,
    // dacp.playstatus
    "caps"=>Uint,
    // dacp.repeatstate
    "carp"=>Uint,
    // dacp.shufflestate
    "cash"=>Uint,
    // dacp.tracklength
    "cast"=>Uint,
    // dacp.su
    "casu"=>Uint,
    // dacp.volumecontrollable
    "cavc"=>Bool,
    // dacp.dacpvisualizerenabled
    "cave"=>Bool,
    // dacp.visualizer
    "cavs"=>Uint,
    // com.apple.itunes.genius-selectable
    "ceGS"=>Str,
    // com.apple.itunes.playqueue-contents-response
    "ceQR"=>Dict,
    // playing metadata
    "ceSD"=>Dict,
    // dmcp.controlprompt
    "cmcp"=>Dict,
    // dmcp.mediakind
    "cmmk"=>Uint,
    // dacp.devicename
    "cmnm"=>Str,
    // dacp.pairinganswer
    "cmpa"=>Dict,
    // dacp.pairingguid
    "cmpg"=>Uint,
    // dmcp.protocolversion
    "cmpr"=>Uint,
    // dmcp.serverrevision
    "cmsr"=>Uint,
    // dmcp.playstatus
    "cmst"=>Dict,
    // dacp.devicetype
    "cmty"=>Str,
    // dmap.dictionary
    "mdcl"=>Dict,
    // dmap.itemid
    "miid"=>Uint,
    // dmap.itemname
    "minm"=>Str,
    // dmap.listing
    "mlcl"=>Dict,
    // dmap.sessionid
    "mlid"=>Uint,
    // dmap.listingitem
    "mlit"=>Dict,
    // dmap.loginresponse
    "mlog"=>Dict,
    // dmap.protocolversion
    "mpro"=>Uint,
    // dmap.returnedcount
    "mrco"=>Uint,
    // dmap.supportsautologout
    "msal"=>Bool,
    // dmap.supportsbrowse
    "msbr"=>Bool,
    // dmap.databasescount
    "msdc"=>Uint,
    // dmap.supportsedit
    "msed"=>Bool,
    // dmap.supportsextensions
    "msex"=>Bool,
    // dmap.supportsindex
    "msix"=>Bool,
    // dmap.loginrequired
    "mslr"=>Bool,
    // dmap.supportspersistentids
    "mspi"=>Bool,
    // dmap.supportsquery
    "msqy"=>Bool,
    // dmap.serverinforesponse
    "msrv"=>Dict,
    // dmap.utctime
    "mstc"=>Uint,
    // dmap.timeoutinterval
    "mstm"=>Uint,
    // dmap.utcoffset
    "msto"=>Uint,
    // dmap.status
    "mstt"=>Uint,
    // dmap.supportsupdate
    "msup"=>Bool,
    // dmap.containercount
    "mtco"=>Uint,
    // Tags with (yet) unknown purpose
    // unknown tag
    "aead"=>Uint,
    // unknown tag
    "aeFR"=>Uint,
    // unknown tag
    "aeSX"=>Uint,
    // unknown tag
    "asse"=>Uint,
    // unknown tag
    "atCV"=>Uint,
    // unknown tag
    "atSV"=>Uint,
    // unknown tag
    "caks"=>Uint,
    // unknown tag
    "caov"=>Uint,
    // unknown tag
    "capl"=>Uint,
    // unknown tag
    "casa"=>Uint,
    // unknown tag
    "casc"=>Uint,
    // unknown tag
    "cass"=>Uint,
    // unknown tag
    "ceQA"=>Uint,
    // unknown tag
    "ceQU"=>Bool,
    // unknown tag
    "ceMQ"=>Bool,
    // unknown tag
    "ceNQ"=>Uint,
    // unknown tag
    "ceNR"=>Uint,
    // unknown tag
    "ceQu"=>Bool,
    // unknown tag
    "cmbe"=>Str,
    // unknown tag
    "cmcc"=>Str,
    // unknown tag
    "cmce"=>Str,
    // unknown tag
    "cmcv"=>Data,
    // unknown tag
    "cmik"=>Uint,
    // unknown tag
    "cmsb"=>Uint,
    // unknown tag
    "cmsc"=>Uint,
    // unknown tag
    "cmsp"=>Uint,
    // unknown tag
    "cmsv"=>Uint,
    // unknown tag
    "cmte"=>Str,
    // unknown tag
    "mscu"=>Uint,
};
