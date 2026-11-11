// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['exports', 'kaitai-struct/KaitaiStream'], factory);
  } else if (typeof exports === 'object' && exports !== null && typeof exports.nodeType !== 'number') {
    factory(exports, require('kaitai-struct/KaitaiStream'));
  } else {
    factory(root.Gzip || (root.Gzip = {}), root.KaitaiStream);
  }
})(typeof self !== 'undefined' ? self : this, function (Gzip_, KaitaiStream) {
var Gzip = (function() {
  function Gzip(_io, _parent, _root) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root || this;

    this._read();
  }
  Gzip.prototype._read = function() {
    this.magic = this._io.readBytes(2);
    if (!((KaitaiStream.byteArrayCompare(this.magic, new Uint8Array([31, 139])) == 0))) {
      throw new KaitaiStream.ValidationNotEqualError(new Uint8Array([31, 139]), this.magic, this._io, "/seq/0");
    }
    this.compressionMethod = this._io.readU1();
    this.flags = this._io.readU1();
    this.mtime = this._io.readU4le();
    this.extraFlags = this._io.readU1();
    this.os = this._io.readU1();
  }

  return Gzip;
})();
Gzip_.Gzip = Gzip;
});
