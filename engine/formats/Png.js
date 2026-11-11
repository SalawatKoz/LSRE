// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['exports', 'kaitai-struct/KaitaiStream'], factory);
  } else if (typeof exports === 'object' && exports !== null && typeof exports.nodeType !== 'number') {
    factory(exports, require('kaitai-struct/KaitaiStream'));
  } else {
    factory(root.Png || (root.Png = {}), root.KaitaiStream);
  }
})(typeof self !== 'undefined' ? self : this, function (Png_, KaitaiStream) {
var Png = (function() {
  function Png(_io, _parent, _root) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root || this;

    this._read();
  }
  Png.prototype._read = function() {
    this.signature = this._io.readBytes(8);
    if (!((KaitaiStream.byteArrayCompare(this.signature, new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])) == 0))) {
      throw new KaitaiStream.ValidationNotEqualError(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), this.signature, this._io, "/seq/0");
    }
    this.ihdrLength = this._io.readU4be();
    this.ihdrType = KaitaiStream.bytesToStr(this._io.readBytes(4), "ASCII");
    this.width = this._io.readU4be();
    this.height = this._io.readU4be();
    this.bitDepth = this._io.readU1();
    this.colorType = this._io.readU1();
    this.compression = this._io.readU1();
    this.filter = this._io.readU1();
    this.interlace = this._io.readU1();
    this.ihdrCrc = this._io.readU4be();
  }

  return Png;
})();
Png_.Png = Png;
});
