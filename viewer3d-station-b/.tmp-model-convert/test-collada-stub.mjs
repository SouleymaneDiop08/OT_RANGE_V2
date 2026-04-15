import fs from 'fs';
import path from 'path';
import { TextEncoder, TextDecoder } from 'util';
import { DOMParser } from '@xmldom/xmldom';

global.DOMParser = DOMParser;
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

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
    return { style:{}, setAttribute(){}, addEventListener(){}, removeEventListener(){} };
  }
};
global.window = global;

const THREE = await import('three');
const { ColladaLoader } = await import('three/examples/jsm/loaders/ColladaLoader.js');
const { GLTFExporter } = await import('three/examples/jsm/exporters/GLTFExporter.js');

const src = '/home/kakashi_/ICSHUB/viewer3d-station-b/frontend/static/assets/extracted/electrical_substation/model.dae';
const out = '/home/kakashi_/ICSHUB/viewer3d-station-b/frontend/static/assets/extracted/electrical_substation/model-converted-raw.glb';
const text = fs.readFileSync(src, 'utf8');
const loader = new ColladaLoader();
const result = loader.parse(text, path.dirname(src) + '/');
let meshes = 0;
result.scene.traverse((o)=>{ if (o.isMesh) { meshes++; if (o.material) { if (Array.isArray(o.material)) o.material.forEach(m=>{ if (m.map) m.map = null; }); else if (o.material.map) o.material.map = null; } } });
console.log('meshes', meshes);
const exporter = new GLTFExporter();
const arrayBuffer = await new Promise((resolve, reject) => {
  exporter.parse(result.scene, resolve, reject, { binary: true, trs: false, onlyVisible: false, maxTextureSize: 1024 });
});
fs.writeFileSync(out, Buffer.from(arrayBuffer));
console.log('wrote', out, fs.statSync(out).size);
