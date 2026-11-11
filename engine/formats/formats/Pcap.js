// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['exports', 'kaitai-struct/KaitaiStream'], factory);
  } else if (typeof exports === 'object' && exports !== null && typeof exports.nodeType !== 'number') {
    factory(exports, require('kaitai-struct/KaitaiStream'));
  } else {
    factory(root.Pcap || (root.Pcap = {}), root.KaitaiStream);
  }
})(typeof self !== 'undefined' ? self : this, function (Pcap_, KaitaiStream) {
var Pcap = (function() {
  function Pcap(_io, _parent, _root) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root || this;

    this._read();
  }
  Pcap.prototype._read = function() {
    this.magic = this._io.readU4le();
    this.versionMajor = this._io.readU2le();
    this.versionMinor = this._io.readU2le();
    this.thiszone = this._io.readS4le();
    this.sigfigs = this._io.readU4le();
    this.snaplen = this._io.readU4le();
    this.network = this._io.readU4le();
  }

  return Pcap;
})();
Pcap_.Pcap = Pcap;
});
