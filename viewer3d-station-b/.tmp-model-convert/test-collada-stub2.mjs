import fs from 'fs';
import path from 'path';
import { TextEncoder, TextDecoder } from 'util';
import { DOMParser } from '@xmldom/xmldom';

global.DOMParser = DOMParser;
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
if (!global.Blob && globalThis.Blob) global.Blob = globalThis.Blob;
class FileReaderPoly {
  constructor(){ this.result = null; this.onloadend = null; }
  async readAsArrayBuffer(blob){ this.result = await blob.arrayBuffer(); if (this.onloadend) this.onloadend(); }
  async readAsDataURL(blob){ const buf = Buffer.from(await blob.arrayBuffer()); this.result = 'data:' + (blob.type || 'application/octet-stream') + ';base64,' + buf.toString('base64'); if (this.onloadend) this.onloadend(); }
}
global.FileReader = FileReaderPoly;
class FakeImage {
  constructor(){ this.listeners = {}; this.width = 1; this.height = 1; this.crossOrigin=''; }
  addEventListener(type, cb){ this.listeners[type] = cb; }
  removeEventListener(type){ delete this.listeners[type]; }
  set src(v){ this._src = v; if (this.listeners.load) setTimeout(() => this.listeners.load(), 0); }
  get src(){ return this._src; }
}
global.Image = FakeImage;
global.document = {
  createElementNS(ns, name) {
    if (name === 'img' || name === 'image') return new FakeImage();
    return { style:{}, setAttribute(){}, addEventListener(){}, removeEventListener(){}, getContext(){ return {}; } };
  }
};
global.window = global;

const { ColladaLoader } = await import('three/examples/jsm/loaders/ColladaLoader.js');
const { GLTFExporter } = await import('three/examples/jsm/exporters/GLTFExporter.js');
const src = '/home/kakashi_/ICSHUB/viewer3d-station-b/frontend/static/assets/extracted/electrical_substation/model.dae';
const out = '/home/kakashi_/ICSHUB/viewer3d-station-b/frontend/static/assets/extracted/electrical_substation/model-converted-raw.glb';
const text = fs.readFileSync(src, 'utf8');
const loader = new ColladaLoader();
const result = loader.parse(text, path.dirname(src) + '/');
let meshes = 0;
result.scene.traverse((o)=>{ if (o.isMesh) { meshes++; if (o.material) { if (Array.isArray(o.material)) o.material = o.material.map(m=>{ m.map = null; return m;}); else o.material.map = null; } } });
console.log('meshes', meshes);
const exporter = new GLTFExporter();
const arrayBuffer = await new Promise((resolve, reject) => exporter.parse(result.scene, resolve, reject, { binary: true, onlyVisible: false, maxTextureSize: 1024 }));
fs.writeFileSync(out, Buffer.from(arrayBuffer));
console.log('wrote', out, fs.statSync(out).size);
