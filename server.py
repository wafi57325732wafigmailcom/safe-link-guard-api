from flask import Flask, request, jsonify
from flask_cors import CORS
import virustotal_python
from base64 import urlsafe_b64encode
import os
import time

app = Flask(__name__)
CORS(app)  # تمكين CORS للسماح لطلبات من الإضافة

# الحصول على API Key من متغير البيئة (أكثر أماناً)
VT_API_KEY = os.environ.get('VT_API_KEY', 'd65c0a63cefa5c3aff1f96f5c72467021c80d0276e0693a740b985895d222db9')

@app.route('/')
def home():
    return jsonify({
        "status": "active",
        "service": "Safe Link Guard API",
        "version": "2.0.0",
        "endpoints": {
            "check_url": "POST /check-url",
            "status": "GET /"
        }
    })

@app.route('/check-url', methods=['POST'])
def check_url():
    try:
        # الحصول على البيانات من طلب الإضافة
        data = request.json
        url = data.get('url', '').strip()
        domain = data.get('domain', '')
        
        if not url:
            return jsonify({
                "error": True,
                "message": "الرجاء إدخال رابط للفحص"
            }), 400
        
        print(f"🔍 فحص الرابط: {url}")
        
        # تحويل الرابط إلى تنسيق Base64 (مطلوب لـ VirusTotal)
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # استخدام VirusTotal API
        with virustotal_python.Virustotal(VT_API_KEY) as vtotal:
            try:
                # محاولة الحصول على التقرير الموجود
                report_resp = vtotal.request(f"urls/{url_id}")
                print("📊 تم العثور على تقرير موجود")
            except virustotal_python.VirustotalError as err:
                if "NotFoundError" in str(err):
                    # إذا لم يكن هناك تقرير، نرسل الرابط للفحص
                    print("🔄 إرسال الرابط للفحص...")
                    scan_resp = vtotal.request("urls", data={"url": url}, method="POST")
                    
                    # انتظار قصير لتحليل VirusTotal
                    time.sleep(2)
                    
                    # محاولة الحصول على التقرير بعد الفحص
                    for attempt in range(3):
                        try:
                            report_resp = vtotal.request(f"urls/{url_id}")
                            print(f"✅ تم الحصول على التقرير بعد {attempt + 1} محاولة")
                            break
                        except:
                            time.sleep(2)
                            continue
                else:
                    raise err
            
            # استخراج النتائج
            stats = report_resp.data['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            suspicious_count = stats['suspicious']
            harmless_count = stats['harmless']
            undetected_count = stats['undetected']
            
            # حساب النسبة المئوية للخطورة
            total_engines = sum(stats.values())
            danger_percentage = (malicious_count + suspicious_count) / total_engines * 100 if total_engines > 0 else 0
            
            # تحديد مستوى الخطورة
            if malicious_count > 5:
                risk_level = "high"
                safe = False
            elif malicious_count > 0:
                risk_level = "medium"
                safe = False
            elif suspicious_count > 2:
                risk_level = "low"
                safe = True
            else:
                risk_level = "none"
                safe = True
            
            # إعداد الرد
            response = {
                "safe": safe,
                "risk_level": risk_level,
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "harmless": harmless_count,
                "total_engines": total_engines,
                "danger_percentage": round(danger_percentage, 1),
                "url": url,
                "domain": domain,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # إضافة تفاصيل إضافية إذا كان الرابط خطيراً
            if malicious_count > 0:
                response["category"] = "malicious"
                response["reason"] = f"تم اكتشاف {malicious_count} محرك يشير إلى أن هذا الرابط ضار"
                response["suggested_action"] = "block"
            elif suspicious_count > 0:
                response["category"] = "suspicious"
                response["reason"] = f"تم اكتشاف {suspicious_count} محرك يشير إلى أن هذا الرابط مشبوه"
                response["suggested_action"] = "warn"
            else:
                response["category"] = "clean"
                response["reason"] = "لم يتم اكتشاف أي تهديدات"
                response["suggested_action"] = "allow"
            
            print(f"📈 النتيجة: {malicious_count} ضار، {suspicious_count} مشبوه")
            return jsonify(response)
            
    except Exception as e:
        print(f"❌ خطأ في معالجة الطلب: {str(e)}")
        return jsonify({
            "error": True,
            "message": f"حدث خطأ في الخادم: {str(e)}",
            "safe": True,  # نسمح بالرابط في حالة الخطأ
            "fallback": True
        }), 500

@app.route('/status', methods=['GET'])
def status():
    return jsonify({
        "status": "online",
        "service": "Safe Link Guard API",
        "version": "2.0.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)