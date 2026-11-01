import { runBenchmark } from '../static/crypto.src.js';
const r = await runBenchmark({ iterations: 20, rsaKeygenRuns: 3 });
console.log(JSON.stringify(r, null, 2));
