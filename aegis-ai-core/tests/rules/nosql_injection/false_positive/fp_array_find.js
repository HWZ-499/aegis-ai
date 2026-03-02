/**
 * FP: Array.find() — 数组方法，不应被识别为 MongoDB 操作。
 * 期望: 无 NOSQL_INJECTION
 */
function findItem(items, id) {
    const item = items.find(x => x.id === id);
    return item;
}

const numbers = [1, 2, 3, 4, 5];
const even = numbers.find(n => n % 2 === 0);
