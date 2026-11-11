// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['exports', 'kaitai-struct/KaitaiStream'], factory);
  } else if (typeof exports === 'object' && exports !== null && typeof exports.nodeType !== 'number') {
    factory(exports, require('kaitai-struct/KaitaiStream'));
  } else {
    factory(root.Sqlite3 || (root.Sqlite3 = {}), root.KaitaiStream);
  }
})(typeof self !== 'undefined' ? self : this, function (Sqlite3_, KaitaiStream) {
var Sqlite3 = (function() {
  function Sqlite3(_io, _parent, _root) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root || this;

    this._read();
  }
  Sqlite3.prototype._read = function() {
    this.magic = this._io.readBytes(16);
    if (!((KaitaiStream.byteArrayCompare(this.magic, new Uint8Array([83, 81, 76, 105, 116, 101, 32, 102, 111, 114, 109, 97, 116, 32, 51, 0])) == 0))) {
      throw new KaitaiStream.ValidationNotEqualError(new Uint8Array([83, 81, 76, 105, 116, 101, 32, 102, 111, 114, 109, 97, 116, 32, 51, 0]), this.magic, this._io, "/seq/0");
    }
    this.pageSize = this._io.readU2be();
    this.writeVersion = this._io.readU1();
    this.readVersion = this._io.readU1();
    this.reservedSpace = this._io.readU1();
    this.maxPayloadFraction = this._io.readU1();
    this.minPayloadFraction = this._io.readU1();
    this.leafPayloadFraction = this._io.readU1();
    this.changeCounter = this._io.readU4be();
    this.databaseSizePages = this._io.readU4be();
    this.freelistTrunkPage = this._io.readU4be();
    this.freelistPages = this._io.readU4be();
    this.schemaCookie = this._io.readU4be();
    this.schemaFormat = this._io.readU4be();
    this.defaultCacheSize = this._io.readU4be();
    this.largestRootPage = this._io.readU4be();
    this.textEncoding = this._io.readU4be();
    this.userVersion = this._io.readU4be();
    this.incrementalVacuum = this._io.readU4be();
    this.applicationId = this._io.readU4be();
    this.reserved = this._io.readBytes(20);
    this.versionValidFor = this._io.readU4be();
    this.sqliteVersion = this._io.readU4be();
  }

  return Sqlite3;
})();
Sqlite3_.Sqlite3 = Sqlite3;
});
