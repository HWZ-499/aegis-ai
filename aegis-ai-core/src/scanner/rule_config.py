# rule_config.py - 规则配置管理
"""
规则配置功能：允许用户自定义规则，启用/禁用特定规则
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from src.analysis.security_rules import VULN_SIGNATURES


class RuleConfig:
    """
    规则配置管理器
    
    支持从配置文件加载规则配置，启用/禁用特定规则
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化规则配置管理器
        
        Args:
            config_path: 配置文件路径（JSON 格式），如果为 None，使用默认配置
        """
        self.config_path = Path(config_path) if config_path else None
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """
        加载配置文件
        
        Returns:
            配置字典
        """
        default_config = {
            "enabled_rules": {},  # 空字典表示启用所有规则
            "disabled_rules": {},  # 空字典表示不禁用任何规则
            "custom_rules": {}    # 自定义规则
        }
        
        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 合并默认配置
                    default_config.update(config)
                    return default_config
            except Exception as e:
                print(f"⚠️  加载配置文件失败: {e}，使用默认配置")
                return default_config
        
        return default_config
    
    def is_rule_enabled(self, vuln_type: str, rule_pattern: str) -> bool:
        """
        检查规则是否启用
        
        Args:
            vuln_type: 漏洞类型（如 'SQL_INJECTION'）
            rule_pattern: 规则模式（正则表达式）
            
        Returns:
            是否启用
        """
        # 检查是否在禁用列表中
        disabled_rules = self.config.get('disabled_rules', {})
        if vuln_type in disabled_rules:
            if rule_pattern in disabled_rules[vuln_type]:
                return False
        
        # 检查是否在启用列表中（如果启用列表不为空）
        enabled_rules = self.config.get('enabled_rules', {})
        if enabled_rules:  # 如果启用列表不为空
            if vuln_type not in enabled_rules:
                return False
            if rule_pattern not in enabled_rules.get(vuln_type, []):
                return False
        
        return True
    
    def get_enabled_signatures(self) -> Dict[str, List[str]]:
        """
        获取启用的漏洞特征库
        
        Returns:
            过滤后的漏洞特征库字典
        """
        enabled_signatures = {}
        
        for vuln_type, patterns in VULN_SIGNATURES.items():
            enabled_patterns = [
                pattern for pattern in patterns
                if self.is_rule_enabled(vuln_type, pattern)
            ]
            
            if enabled_patterns:
                enabled_signatures[vuln_type] = enabled_patterns
        
        # 添加自定义规则
        custom_rules = self.config.get('custom_rules', {})
        for vuln_type, patterns in custom_rules.items():
            if vuln_type in enabled_signatures:
                enabled_signatures[vuln_type].extend(patterns)
            else:
                enabled_signatures[vuln_type] = patterns
        
        return enabled_signatures
    
    def save_config(self, output_path: Optional[str] = None):
        """
        保存配置到文件
        
        Args:
            output_path: 输出文件路径，如果为 None，使用当前配置路径
        """
        save_path = Path(output_path) if output_path else self.config_path
        
        if not save_path:
            print("⚠️  未指定配置文件路径")
            return
        
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 配置已保存到: {save_path}")
    
    def disable_rule(self, vuln_type: str, rule_pattern: str):
        """
        禁用特定规则
        
        Args:
            vuln_type: 漏洞类型
            rule_pattern: 规则模式
        """
        if 'disabled_rules' not in self.config:
            self.config['disabled_rules'] = {}
        
        if vuln_type not in self.config['disabled_rules']:
            self.config['disabled_rules'][vuln_type] = []
        
        if rule_pattern not in self.config['disabled_rules'][vuln_type]:
            self.config['disabled_rules'][vuln_type].append(rule_pattern)
    
    def enable_rule(self, vuln_type: str, rule_pattern: str):
        """
        启用特定规则（从禁用列表中移除）
        
        Args:
            vuln_type: 漏洞类型
            rule_pattern: 规则模式
        """
        disabled_rules = self.config.get('disabled_rules', {})
        if vuln_type in disabled_rules:
            if rule_pattern in disabled_rules[vuln_type]:
                disabled_rules[vuln_type].remove(rule_pattern)
    
    def add_custom_rule(self, vuln_type: str, rule_pattern: str):
        """
        添加自定义规则
        
        Args:
            vuln_type: 漏洞类型
            rule_pattern: 规则模式（正则表达式）
        """
        if 'custom_rules' not in self.config:
            self.config['custom_rules'] = {}
        
        if vuln_type not in self.config['custom_rules']:
            self.config['custom_rules'][vuln_type] = []
        
        if rule_pattern not in self.config['custom_rules'][vuln_type]:
            self.config['custom_rules'][vuln_type].append(rule_pattern)


def create_default_config(output_path: str) -> Path:
    """
    创建默认配置文件模板
    
    Args:
        output_path: 输出文件路径
        
    Returns:
        配置文件路径
    """
    config_path = Path(output_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    default_config = {
        "description": "Aegis 规则配置文件",
        "version": "1.0",
        "enabled_rules": {
            "comment": "启用列表为空 {} 表示启用所有规则",
            "example": {}
        },
        "disabled_rules": {
            "comment": "禁用特定规则，格式: {漏洞类型: [规则模式列表]}",
            "example": {
                "RCE_COMMAND_EXEC": [
                    "r\"os\\.system\\s*\\(\""
                ]
            }
        },
        "custom_rules": {
            "comment": "自定义规则，格式: {漏洞类型: [规则模式列表]}",
            "example": {
                "CUSTOM_VULN": [
                    "r\"custom_pattern\""
                ]
            }
        }
    }
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 默认配置文件已创建: {config_path}")
    return config_path


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='规则配置管理工具')
    parser.add_argument('--config', help='配置文件路径')
    parser.add_argument('--create-default', help='创建默认配置文件')
    parser.add_argument('--list', action='store_true', help='列出所有可用规则')
    parser.add_argument('--disable', nargs=2, metavar=('TYPE', 'PATTERN'), help='禁用规则')
    parser.add_argument('--enable', nargs=2, metavar=('TYPE', 'PATTERN'), help='启用规则')
    parser.add_argument('--add-custom', nargs=2, metavar=('TYPE', 'PATTERN'), help='添加自定义规则')
    
    args = parser.parse_args()
    
    if args.create_default:
        create_default_config(args.create_default)
    else:
        config = RuleConfig(args.config)
        
        if args.list:
            print("📋 可用规则:")
            for vuln_type, patterns in VULN_SIGNATURES.items():
                print(f"\n{vuln_type}:")
                for pattern in patterns:
                    enabled = "✅" if config.is_rule_enabled(vuln_type, pattern) else "❌"
                    print(f"  {enabled} {pattern}")
        
        if args.disable:
            vuln_type, pattern = args.disable
            config.disable_rule(vuln_type, pattern)
            config.save_config()
        
        if args.enable:
            vuln_type, pattern = args.enable
            config.enable_rule(vuln_type, pattern)
            config.save_config()
        
        if args.add_custom:
            vuln_type, pattern = args.add_custom
            config.add_custom_rule(vuln_type, pattern)
            config.save_config()
