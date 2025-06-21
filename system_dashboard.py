"""
SYSTEM DASHBOARD
Kapsamlı sistem izleme ve dashboard
"""

import asyncio
import logging
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
import json
import threading
import numpy as np
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage: Dict
    network_io: Dict
    active_connections: int

class SystemDashboard:
    def __init__(self):
        # System metrics history
        self.metrics_history = deque(maxlen=1440)  # 24 hours of minute-by-minute data
        
        # Component status tracking
        self.component_status = {
            'ml_models': {},
            'external_apis': {},
            'databases': {},
            'security_systems': {},
            'background_tasks': {}
        }
        
        # Performance metrics
        self.performance_metrics = {
            'api_response_times': deque(maxlen=1000),
            'ml_prediction_times': deque(maxlen=1000),
            'database_query_times': deque(maxlen=1000),
            'external_api_times': deque(maxlen=1000),
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_confidence': deque(maxlen=1000)
        }
        
        # Alert system
        self.alerts = deque(maxlen=100)
        self.alert_thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'disk_usage': 90.0,
            'response_time': 5.0,  # seconds
            'error_rate': 0.05,    # 5%
            'prediction_accuracy': 0.8  # 80%
        }
        
        # Real-time monitoring flags
        self.monitoring_active = False
        self.monitoring_thread = None
        
        # Dashboard data cache
        self.dashboard_cache = {}
        self.cache_updated = None
        self.cache_ttl = 30  # seconds
        
        # Component health scores
        self.health_scores = {
            'overall': 100,
            'api_performance': 100,
            'ml_accuracy': 100,
            'external_services': 100,
            'security_status': 100,
            'system_resources': 100
        }
        
    def start_monitoring(self) -> None:
        """Sistem izlemeyi başlat"""
        try:
            if not self.monitoring_active:
                self.monitoring_active = True
                self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
                self.monitoring_thread.start()
                logger.info("🚀 System monitoring started")
        except Exception as e:
            logger.error(f"❌ Failed to start monitoring: {e}")
    
    def stop_monitoring(self) -> None:
        """Sistem izlemeyi durdur"""
        try:
            self.monitoring_active = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5)
            logger.info("⏹️ System monitoring stopped")
        except Exception as e:
            logger.error(f"❌ Failed to stop monitoring: {e}")
    
    def _monitoring_loop(self) -> None:
        """Ana izleme döngüsü"""
        while self.monitoring_active:
            try:
                # Collect system metrics
                metrics = self._collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # Check for alerts
                self._check_alert_conditions(metrics)
                
                # Update component status
                self._update_component_status()
                
                # Calculate health scores
                self._update_health_scores()
                
                # Sleep for next cycle
                time.sleep(60)  # Collect metrics every minute
                
            except Exception as e:
                logger.error(f"❌ Monitoring loop error: {e}")
                time.sleep(60)
    
    def _collect_system_metrics(self) -> SystemMetrics:
        """Sistem metriklerini topla"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        'total': partition_usage.total,
                        'used': partition_usage.used,
                        'free': partition_usage.free,
                        'percent': (partition_usage.used / partition_usage.total) * 100
                    }
                except PermissionError:
                    continue
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_data = {
                'bytes_sent': network_io.bytes_sent,
                'bytes_recv': network_io.bytes_recv,
                'packets_sent': network_io.packets_sent,
                'packets_recv': network_io.packets_recv
            }
            
            # Active connections
            active_connections = len(psutil.net_connections())
            
            return SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage=disk_usage,
                network_io=network_data,
                active_connections=active_connections
            )
            
        except Exception as e:
            logger.error(f"❌ System metrics collection error: {e}")
            return SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=0,
                memory_percent=0,
                disk_usage={},
                network_io={},
                active_connections=0
            )
    
    def _check_alert_conditions(self, metrics: SystemMetrics) -> None:
        """Alert koşullarını kontrol et"""
        try:
            alerts_triggered = []
            
            # CPU usage alert
            if metrics.cpu_percent > self.alert_thresholds['cpu_usage']:
                alerts_triggered.append({
                    'type': 'cpu_high',
                    'message': f'High CPU usage: {metrics.cpu_percent:.1f}%',
                    'severity': 'warning' if metrics.cpu_percent < 95 else 'critical',
                    'value': metrics.cpu_percent,
                    'threshold': self.alert_thresholds['cpu_usage']
                })
            
            # Memory usage alert
            if metrics.memory_percent > self.alert_thresholds['memory_usage']:
                alerts_triggered.append({
                    'type': 'memory_high',
                    'message': f'High memory usage: {metrics.memory_percent:.1f}%',
                    'severity': 'warning' if metrics.memory_percent < 95 else 'critical',
                    'value': metrics.memory_percent,
                    'threshold': self.alert_thresholds['memory_usage']
                })
            
            # Disk usage alerts
            for mount_point, usage_data in metrics.disk_usage.items():
                if usage_data['percent'] > self.alert_thresholds['disk_usage']:
                    alerts_triggered.append({
                        'type': 'disk_high',
                        'message': f'High disk usage on {mount_point}: {usage_data["percent"]:.1f}%',
                        'severity': 'warning' if usage_data['percent'] < 98 else 'critical',
                        'value': usage_data['percent'],
                        'threshold': self.alert_thresholds['disk_usage']
                    })
            
            # Response time alerts
            if self.performance_metrics['api_response_times']:
                avg_response_time = np.mean(list(self.performance_metrics['api_response_times'])[-10:])
                if avg_response_time > self.alert_thresholds['response_time']:
                    alerts_triggered.append({
                        'type': 'response_time_high',
                        'message': f'High API response time: {avg_response_time:.2f}s',
                        'severity': 'warning',
                        'value': avg_response_time,
                        'threshold': self.alert_thresholds['response_time']
                    })
            
            # Error rate alerts
            total_requests = self.performance_metrics['total_requests']
            failed_requests = self.performance_metrics['failed_requests']
            if total_requests > 100:  # Only check if we have enough data
                error_rate = failed_requests / total_requests
                if error_rate > self.alert_thresholds['error_rate']:
                    alerts_triggered.append({
                        'type': 'error_rate_high',
                        'message': f'High error rate: {error_rate:.2%}',
                        'severity': 'warning' if error_rate < 0.1 else 'critical',
                        'value': error_rate,
                        'threshold': self.alert_thresholds['error_rate']
                    })
            
            # Store alerts
            for alert in alerts_triggered:
                alert['timestamp'] = datetime.now().isoformat()
                self.alerts.append(alert)
                logger.warning(f"🚨 Alert: {alert['message']}")
                
        except Exception as e:
            logger.error(f"❌ Alert check error: {e}")
    
    def _update_component_status(self) -> None:
        """Komponenet durumlarını güncelle"""
        try:
            # ML Models status (would integrate with your actual models)
            self.component_status['ml_models'] = {
                'phishing_model': {'status': 'healthy', 'last_prediction': datetime.now()},
                'cybersecurity_model': {'status': 'healthy', 'last_prediction': datetime.now()},
                'ensemble_analyzer': {'status': 'healthy', 'accuracy': 0.95}
            }
            
            # External APIs status
            self.component_status['external_apis'] = {
                'virustotal': {'status': 'healthy', 'response_time': 0.5, 'rate_limit_remaining': 950},
                'google_safe_browsing': {'status': 'healthy', 'response_time': 0.3, 'rate_limit_remaining': 9800}
            }
            
            # Database status
            self.component_status['databases'] = {
                'supabase': {'status': 'healthy', 'connection_pool': 5, 'query_performance': 0.1}
            }
            
            # Security systems
            self.component_status['security_systems'] = {
                'rate_limiter': {'status': 'active', 'blocked_ips': 3, 'active_limits': 12},
                'api_authentication': {'status': 'active', 'valid_keys': 25}
            }
            
            # Background tasks
            self.component_status['background_tasks'] = {
                'threat_monitoring': {'status': 'running', 'last_scan': datetime.now()},
                'model_optimization': {'status': 'scheduled', 'next_run': datetime.now() + timedelta(hours=1)}
            }
            
        except Exception as e:
            logger.error(f"❌ Component status update error: {e}")
    
    def _update_health_scores(self) -> None:
        """Sağlık skorlarını güncelle"""
        try:
            # System resources health
            if self.metrics_history:
                latest_metrics = self.metrics_history[-1]
                
                cpu_score = max(0, 100 - latest_metrics.cpu_percent)
                memory_score = max(0, 100 - latest_metrics.memory_percent)
                
                # Disk health (average across all disks)
                disk_scores = []
                for usage_data in latest_metrics.disk_usage.values():
                    disk_scores.append(max(0, 100 - usage_data['percent']))
                disk_score = np.mean(disk_scores) if disk_scores else 100
                
                self.health_scores['system_resources'] = int(np.mean([cpu_score, memory_score, disk_score]))
            
            # API performance health
            if self.performance_metrics['api_response_times']:
                avg_response_time = np.mean(list(self.performance_metrics['api_response_times'])[-50:])
                # Score based on response time (5s = 0 score, 0.5s = 100 score)
                response_score = max(0, 100 - (avg_response_time - 0.5) * 20)
                self.health_scores['api_performance'] = int(response_score)
            
            # ML accuracy health
            if self.performance_metrics['average_confidence']:
                avg_confidence = np.mean(list(self.performance_metrics['average_confidence'])[-50:])
                self.health_scores['ml_accuracy'] = int(avg_confidence * 100)
            
            # External services health
            external_score = 100
            for service_name, service_data in self.component_status['external_apis'].items():
                if service_data['status'] != 'healthy':
                    external_score -= 30
            self.health_scores['external_services'] = max(0, external_score)
            
            # Security status health
            security_score = 100
            recent_alerts = [alert for alert in self.alerts 
                           if datetime.fromisoformat(alert['timestamp']) > datetime.now() - timedelta(hours=1)]
            critical_alerts = [alert for alert in recent_alerts if alert['severity'] == 'critical']
            
            security_score -= len(critical_alerts) * 20
            security_score -= len(recent_alerts) * 5
            self.health_scores['security_status'] = max(0, security_score)
            
            # Overall health (weighted average)
            weights = {
                'api_performance': 0.25,
                'ml_accuracy': 0.25,
                'external_services': 0.2,
                'security_status': 0.15,
                'system_resources': 0.15
            }
            
            overall_score = sum(
                self.health_scores[component] * weight
                for component, weight in weights.items()
            )
            self.health_scores['overall'] = int(overall_score)
            
        except Exception as e:
            logger.error(f"❌ Health score update error: {e}")
    
    async def get_dashboard_data(self, force_refresh: bool = False) -> Dict:
        """Dashboard verilerini getir"""
        try:
            current_time = datetime.now()
            
            # Check cache
            if (not force_refresh and self.cache_updated and 
                current_time - self.cache_updated < timedelta(seconds=self.cache_ttl)):
                return self.dashboard_cache
            
            # Generate fresh dashboard data
            dashboard_data = {
                'timestamp': current_time.isoformat(),
                'system_health': self.health_scores,
                'current_metrics': await self._get_current_metrics(),
                'performance_summary': await self._get_performance_summary(),
                'component_status': self.component_status,
                'recent_alerts': list(self.alerts)[-10:],  # Last 10 alerts
                'system_statistics': await self._get_system_statistics(),
                'trend_analysis': await self._get_trend_analysis(),
                'capacity_planning': await self._get_capacity_planning(),
                'ml_model_performance': await self._get_ml_performance_summary()
            }
            
            # Update cache
            self.dashboard_cache = dashboard_data
            self.cache_updated = current_time
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"❌ Dashboard data error: {e}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    async def _get_current_metrics(self) -> Dict:
        """Güncel metrikleri getir"""
        try:
            if not self.metrics_history:
                return {}
            
            latest = self.metrics_history[-1]
            return {
                'cpu_percent': latest.cpu_percent,
                'memory_percent': latest.memory_percent,
                'disk_usage': latest.disk_usage,
                'active_connections': latest.active_connections,
                'uptime': self._get_system_uptime(),
                'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
            }
        except Exception as e:
            logger.error(f"❌ Current metrics error: {e}")
            return {}
    
    def _get_system_uptime(self) -> float:
        """Sistem uptime'ını getir (saat cinsinden)"""
        try:
            boot_time = psutil.boot_time()
            return (time.time() - boot_time) / 3600  # Convert to hours
        except:
            return 0
    
    async def _get_performance_summary(self) -> Dict:
        """Performans özetini getir"""
        try:
            summary = {
                'total_requests': self.performance_metrics['total_requests'],
                'successful_requests': self.performance_metrics['successful_requests'],
                'failed_requests': self.performance_metrics['failed_requests'],
                'success_rate': 0,
                'average_response_time': 0,
                'average_ml_time': 0,
                'average_confidence': 0
            }
            
            # Calculate success rate
            if self.performance_metrics['total_requests'] > 0:
                summary['success_rate'] = (
                    self.performance_metrics['successful_requests'] / 
                    self.performance_metrics['total_requests']
                )
            
            # Calculate average response time
            if self.performance_metrics['api_response_times']:
                summary['average_response_time'] = np.mean(
                    list(self.performance_metrics['api_response_times'])
                )
            
            # Calculate average ML prediction time
            if self.performance_metrics['ml_prediction_times']:
                summary['average_ml_time'] = np.mean(
                    list(self.performance_metrics['ml_prediction_times'])
                )
            
            # Calculate average confidence
            if self.performance_metrics['average_confidence']:
                summary['average_confidence'] = np.mean(
                    list(self.performance_metrics['average_confidence'])
                )
            
            return summary
            
        except Exception as e:
            logger.error(f"❌ Performance summary error: {e}")
            return {}
    
    async def _get_system_statistics(self) -> Dict:
        """Sistem istatistiklerini getir"""
        try:
            return {
                'monitoring_active': self.monitoring_active,
                'metrics_collected': len(self.metrics_history),
                'alerts_total': len(self.alerts),
                'components_monitored': sum(len(components) for components in self.component_status.values()),
                'data_retention_hours': 24,
                'cache_hit_ratio': 0.85,  # Example
                'last_backup': datetime.now() - timedelta(hours=6)  # Example
            }
        except Exception as e:
            logger.error(f"❌ System statistics error: {e}")
            return {}
    
    async def _get_trend_analysis(self) -> Dict:
        """Trend analizini getir"""
        try:
            if len(self.metrics_history) < 10:
                return {'insufficient_data': True}
            
            # Get last 60 minutes of data
            recent_metrics = list(self.metrics_history)[-60:]
            
            # CPU trend
            cpu_values = [m.cpu_percent for m in recent_metrics]
            cpu_trend = 'stable'
            if len(cpu_values) >= 10:
                first_half = np.mean(cpu_values[:len(cpu_values)//2])
                second_half = np.mean(cpu_values[len(cpu_values)//2:])
                diff = second_half - first_half
                if diff > 10:
                    cpu_trend = 'increasing'
                elif diff < -10:
                    cpu_trend = 'decreasing'
            
            # Memory trend
            memory_values = [m.memory_percent for m in recent_metrics]
            memory_trend = 'stable'
            if len(memory_values) >= 10:
                first_half = np.mean(memory_values[:len(memory_values)//2])
                second_half = np.mean(memory_values[len(memory_values)//2:])
                diff = second_half - first_half
                if diff > 5:
                    memory_trend = 'increasing'
                elif diff < -5:
                    memory_trend = 'decreasing'
            
            return {
                'cpu_trend': cpu_trend,
                'memory_trend': memory_trend,
                'prediction': self._predict_resource_usage(),
                'recommendations': self._generate_trend_recommendations(cpu_trend, memory_trend)
            }
            
        except Exception as e:
            logger.error(f"❌ Trend analysis error: {e}")
            return {}
    
    def _predict_resource_usage(self) -> Dict:
        """Kaynak kullanım tahmini"""
        try:
            if len(self.metrics_history) < 30:
                return {'insufficient_data': True}
            
            # Simple linear prediction for next hour
            recent_metrics = list(self.metrics_history)[-30:]  # Last 30 minutes
            
            cpu_values = [m.cpu_percent for m in recent_metrics]
            memory_values = [m.memory_percent for m in recent_metrics]
            
            # Linear regression for prediction
            x = np.arange(len(cpu_values))
            
            cpu_slope = np.polyfit(x, cpu_values, 1)[0]
            memory_slope = np.polyfit(x, memory_values, 1)[0]
            
            # Predict for next 60 minutes
            cpu_prediction = cpu_values[-1] + (cpu_slope * 60)
            memory_prediction = memory_values[-1] + (memory_slope * 60)
            
            return {
                'next_hour_cpu': max(0, min(100, cpu_prediction)),
                'next_hour_memory': max(0, min(100, memory_prediction)),
                'cpu_slope': cpu_slope,
                'memory_slope': memory_slope
            }
            
        except Exception as e:
            logger.error(f"❌ Resource prediction error: {e}")
            return {}
    
    def _generate_trend_recommendations(self, cpu_trend: str, memory_trend: str) -> List[str]:
        """Trend tabanlı öneriler"""
        recommendations = []
        
        if cpu_trend == 'increasing':
            recommendations.append("🔥 CPU usage is increasing - consider scaling")
        elif cpu_trend == 'decreasing':
            recommendations.append("📉 CPU usage is decreasing - resources can be optimized")
        
        if memory_trend == 'increasing':
            recommendations.append("🧠 Memory usage is increasing - monitor for memory leaks")
        
        if cpu_trend == 'increasing' and memory_trend == 'increasing':
            recommendations.append("⚡ Both CPU and memory increasing - immediate attention needed")
        
        return recommendations
    
    async def _get_capacity_planning(self) -> Dict:
        """Kapasite planlaması"""
        try:
            current_load = {
                'requests_per_hour': self.performance_metrics['total_requests'],
                'avg_response_time': np.mean(list(self.performance_metrics['api_response_times'])) 
                                   if self.performance_metrics['api_response_times'] else 0
            }
            
            # Estimate capacity based on current performance
            max_requests_per_hour = 10000  # Example based on your system
            current_utilization = current_load['requests_per_hour'] / max_requests_per_hour
            
            return {
                'current_utilization': current_utilization,
                'estimated_max_capacity': max_requests_per_hour,
                'time_to_capacity': self._estimate_time_to_capacity(current_utilization),
                'scaling_recommendation': self._get_scaling_recommendation(current_utilization)
            }
            
        except Exception as e:
            logger.error(f"❌ Capacity planning error: {e}")
            return {}
    
    def _estimate_time_to_capacity(self, current_utilization: float) -> str:
        """Kapasite dolma tahmini"""
        if current_utilization >= 0.9:
            return "Critical - within hours"
        elif current_utilization >= 0.7:
            return "High - within days"
        elif current_utilization >= 0.5:
            return "Medium - within weeks"
        else:
            return "Low - months or more"
    
    def _get_scaling_recommendation(self, utilization: float) -> str:
        """Ölçeklendirme önerisi"""
        if utilization >= 0.8:
            return "Scale immediately - add more resources"
        elif utilization >= 0.6:
            return "Plan scaling - prepare additional resources"
        elif utilization >= 0.4:
            return "Monitor closely - scaling may be needed soon"
        else:
            return "No immediate scaling needed"
    
    async def _get_ml_performance_summary(self) -> Dict:
        """ML performans özetini getir"""
        try:
            # This would integrate with your actual ML models
            return {
                'model_count': 7,
                'ensemble_accuracy': 0.95,
                'prediction_confidence_avg': 0.87,
                'models_healthy': 7,
                'models_warning': 0,
                'models_error': 0,
                'last_model_update': datetime.now() - timedelta(hours=2),
                'next_training_scheduled': datetime.now() + timedelta(hours=6)
            }
        except Exception as e:
            logger.error(f"❌ ML performance summary error: {e}")
            return {}
    
    def add_performance_metric(self, metric_type: str, value: float) -> None:
        """Performans metriği ekle"""
        try:
            if metric_type in self.performance_metrics:
                if isinstance(self.performance_metrics[metric_type], deque):
                    self.performance_metrics[metric_type].append(value)
                else:
                    self.performance_metrics[metric_type] = value
        except Exception as e:
            logger.error(f"❌ Add performance metric error: {e}")
    
    def record_request(self, success: bool, response_time: float, confidence: Optional[float] = None) -> None:
        """İstek kaydı"""
        try:
            self.performance_metrics['total_requests'] += 1
            
            if success:
                self.performance_metrics['successful_requests'] += 1
            else:
                self.performance_metrics['failed_requests'] += 1
            
            self.performance_metrics['api_response_times'].append(response_time)
            
            if confidence is not None:
                self.performance_metrics['average_confidence'].append(confidence)
                
        except Exception as e:
            logger.error(f"❌ Record request error: {e}")

# Global instance
system_dashboard = SystemDashboard() 