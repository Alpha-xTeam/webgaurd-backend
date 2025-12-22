from flask import Blueprint, jsonify, request
from api.auth import token_required
import requests
from datetime import datetime, timedelta
import os

api_bp = Blueprint('news', __name__)

# News API configuration
NEWS_API_KEY = os.getenv('NEWS_API_KEY', 'your_api_key_here')
NEWS_API_URL = 'https://newsapi.org/v2/everything'

# Cache for news articles (to avoid hitting API limits)
_news_cache = {
    'articles': [],
    'last_updated': None
}
CACHE_DURATION_MINUTES = 30

def get_tech_news_from_api():
    """Fetch tech news from News API"""
    try:
        # Check cache first
        if _news_cache['last_updated']:
            time_diff = datetime.now() - _news_cache['last_updated']
            if time_diff.total_seconds() < CACHE_DURATION_MINUTES * 60:
                return _news_cache['articles']
        
        # Define tech-related queries
        queries = [
            'cybersecurity OR "cyber security"',
            '"artificial intelligence" OR AI OR "machine learning"',
            '"web development" OR programming OR coding',
            '"cloud computing" OR AWS OR Azure',
            'blockchain OR cryptocurrency',
            '"mobile development" OR "app development"'
        ]
        
        all_articles = []
        
        for i, query in enumerate(queries):
            params = {
                'q': query,
                'language': 'en',
                'sortBy': 'publishedAt',
                'pageSize': 5,
                'apiKey': NEWS_API_KEY,
                'from': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            }
            
            response = requests.get(NEWS_API_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                articles = data.get('articles', [])
                
                # Map category based on query index
                category_map = ['security', 'ai', 'web', 'cloud', 'blockchain', 'mobile']
                
                for article in articles:
                    # Skip articles without images
                    if not article.get('urlToImage'):
                        continue
                    
                    all_articles.append({
                        'id': len(all_articles) + 1,
                        'title': article.get('title', 'بدون عنوان'),
                        'summary': article.get('description', 'لا يوجد ملخص متاح'),
                        'content': article.get('content', article.get('description', '')),
                        'author': article.get('author', 'كاتب مجهول'),
                        'date': article.get('publishedAt', datetime.now().isoformat()),
                        'category': category_map[i],
                        'image': article.get('urlToImage', ''),
                        'source': article.get('url', ''),
                        'readTime': 5  # Default read time
                    })
        
        # Update cache
        _news_cache['articles'] = all_articles[:30]  # Limit to 30 articles
        _news_cache['last_updated'] = datetime.now()
        
        return all_articles[:30]
        
    except Exception as e:
        print(f"Error fetching news from API: {e}")
        return get_fallback_news()

def get_fallback_news():
    """Fallback tech news when API is unavailable"""
    return [
        {
            'id': 1,
            'title': 'أحدث تطورات الأمن السيبراني في 2025',
            'summary': 'نظرة شاملة على أحدث التهديدات السيبرانية وكيفية الحماية منها في العصر الرقمي الحديث.',
            'content': 'مع تزايد الهجمات السيبرانية، أصبح من الضروري فهم أحدث تقنيات الحماية والأمان. يتناول هذا المقال أهم الثغرات الأمنية المكتشفة حديثاً وكيفية التصدي لها باستخدام أحدث الأدوات والتقنيات.',
            'author': 'فريق WebGuard-IR',
            'date': datetime.now().isoformat(),
            'category': 'security',
            'image': 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 8
        },
        {
            'id': 2,
            'title': 'الذكاء الاصطناعي يغير مستقبل البرمجة',
            'summary': 'كيف تساعد أدوات الذكاء الاصطناعي المطورين في كتابة كود أفضل وأسرع.',
            'content': 'أدوات مثل GitHub Copilot و ChatGPT تحدث ثورة في طريقة كتابة الأكواد البرمجية. تعرف على كيفية استخدام هذه الأدوات لتحسين إنتاجيتك كمطور.',
            'author': 'أحمد محمد',
            'date': (datetime.now() - timedelta(days=1)).isoformat(),
            'category': 'ai',
            'image': 'https://images.unsplash.com/photo-1677442136019-21780ecad995?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 6
        },
        {
            'id': 3,
            'title': 'أفضل ممارسات تطوير الويب الحديث',
            'summary': 'دليل شامل لأحدث تقنيات وأدوات تطوير تطبيقات الويب في 2025.',
            'content': 'من React إلى Next.js، تعرف على أحدث الأطر والمكتبات التي يستخدمها المطورون المحترفون لبناء تطبيقات ويب سريعة وآمنة.',
            'author': 'سارة علي',
            'date': (datetime.now() - timedelta(days=2)).isoformat(),
            'category': 'web',
            'image': 'https://images.unsplash.com/photo-1547658719-da2b51169166?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 10
        },
        {
            'id': 4,
            'title': 'الحوسبة السحابية: AWS vs Azure vs Google Cloud',
            'summary': 'مقارنة شاملة بين أكبر ثلاث منصات للحوسبة السحابية في العالم.',
            'content': 'اختيار المنصة السحابية المناسبة يمكن أن يحدث فرقاً كبيراً في نجاح مشروعك. نقارن بين الميزات والأسعار والأداء لكل منصة.',
            'author': 'محمد حسن',
            'date': (datetime.now() - timedelta(days=3)).isoformat(),
            'category': 'cloud',
            'image': 'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 12
        },
        {
            'id': 5,
            'title': 'البلوك تشين: أكثر من مجرد عملات رقمية',
            'summary': 'استكشاف التطبيقات العملية لتقنية البلوك تشين خارج نطاق العملات المشفرة.',
            'content': 'تقنية البلوك تشين تستخدم الآن في مجالات متعددة من سلاسل التوريد إلى الرعاية الصحية. تعرف على كيفية استخدام هذه التقنية الثورية.',
            'author': 'ليلى أحمد',
            'date': (datetime.now() - timedelta(days=4)).isoformat(),
            'category': 'blockchain',
            'image': 'https://images.unsplash.com/photo-1639762681485-074b7f938ba0?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 7
        },
        {
            'id': 6,
            'title': 'تطوير تطبيقات الموبايل: Flutter vs React Native',
            'summary': 'أيهما أفضل لمشروعك القادم؟ مقارنة تفصيلية بين أشهر إطارات تطوير التطبيقات.',
            'content': 'Flutter و React Native هما الخياران الأكثر شعبية لتطوير تطبيقات الموبايل متعددة المنصات. نستعرض مزايا وعيوب كل منهما.',
            'author': 'عمر خالد',
            'date': (datetime.now() - timedelta(days=5)).isoformat(),
            'category': 'mobile',
            'image': 'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 9
        },
        {
            'id': 7,
            'title': 'اختبار الاختراق: دليل المبتدئين',
            'summary': 'كيف تبدأ مسيرتك المهنية في مجال اختبار الاختراق والأمن السيبراني.',
            'content': 'اختبار الاختراق من أكثر المجالات طلباً في سوق العمل. تعرف على الأدوات والمهارات الأساسية التي تحتاجها للبدء.',
            'author': 'فريق WebGuard-IR',
            'date': (datetime.now() - timedelta(days=6)).isoformat(),
            'category': 'security',
            'image': 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 15
        },
        {
            'id': 8,
            'title': 'التعلم الآلي للمبتدئين: من أين تبدأ؟',
            'summary': 'خارطة طريق شاملة لتعلم أساسيات التعلم الآلي والذكاء الاصطناعي.',
            'content': 'التعلم الآلي ليس بالصعوبة التي تتخيلها. نقدم لك دليلاً خطوة بخطوة للبدء في هذا المجال المثير.',
            'author': 'نور الدين',
            'date': (datetime.now() - timedelta(days=7)).isoformat(),
            'category': 'ai',
            'image': 'https://images.unsplash.com/photo-1555255707-c07966088b7b?w=800',
            'source': 'https://webguard-ir.com',
            'readTime': 11
        }
    ]

@api_bp.route('/news', methods=['GET'])
@token_required
def get_news(current_user):
    """Get technology news articles"""
    try:
        # Try to get news from API, fallback to static content if fails
        articles = get_tech_news_from_api()
        
        return jsonify({
            'success': True,
            'articles': articles,
            'cached': _news_cache['last_updated'] is not None
        }), 200
        
    except Exception as e:
        print(f"Error in get_news: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'articles': get_fallback_news()
        }), 200  # Return 200 with fallback data

@api_bp.route('/news/refresh', methods=['POST'])
@token_required
def refresh_news(current_user):
    """Force refresh news cache"""
    try:
        # Clear cache
        _news_cache['last_updated'] = None
        _news_cache['articles'] = []
        
        # Fetch fresh news
        articles = get_tech_news_from_api()
        
        return jsonify({
            'success': True,
            'message': 'News cache refreshed',
            'articles': articles
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500