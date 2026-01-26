import { Component, ChangeDetectorRef } from '@angular/core'; // 👈 1. 引入刷新神器
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import axios from 'axios';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule], 
  templateUrl: './app.html',
  styleUrls: ['./app.scss']
})
export class App {
  editorOptions = {theme: 'vs-dark', language: 'python'};
  code: string = 'import sqlite3\n\n# 在这里输入代码...'; 
  
  loading = false;
  results: any[] = [];

  // 👈 2. 在构造函数里“聘请”这个刷新神器
  constructor(private cdr: ChangeDetectorRef) {} 

  async scanCode() {
    this.loading = true;
    this.results = [];
    
    try {
      console.log("发射！");
      const response = await axios.post('http://localhost:3000/api/scan', { code: this.code });
      
      this.results = response.data; // 数据装填完毕
      
      // 👈 3. 终极绝杀：强行命令 Angular 刷新页面！
      this.cdr.detectChanges(); 
      console.log("数据已强行渲染！", this.results);
      
    } catch (error) {
      alert('扫描失败，请检查网络！');
    } finally {
      this.loading = false;
      this.cdr.detectChanges(); // 结束 loading 状态时也刷新一下
    }
  }
}