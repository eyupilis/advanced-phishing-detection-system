import pickle

with open('phishing_urls_model_best_info.pkl', 'rb') as f:
    info = pickle.load(f)

print('🚀 Phishing URLs Model Results')
print('=' * 50)
print(f'Model Type: {info["model_type"]}')
print(f'Selected Features: {len(info["feature_names"])}')
print()
print('📊 Model Performance:')
for model, metrics in info['model_performance'].items():
    print(f'\n{model}:')
    print(f'  Accuracy: {metrics["accuracy"]:.4f}')
    print(f'  Precision: {metrics["precision"]:.4f}')  
    print(f'  Recall: {metrics["recall"]:.4f}')
    print(f'  F1-Score: {metrics["f1_score"]:.4f}')
    print(f'  AUC: {metrics["auc_score"]:.4f}')
    print(f'  CV Score: {metrics["cv_mean"]:.4f} ± {metrics["cv_std"]:.4f}')

print(f'\n🎯 Selected Features:')
for i, feature in enumerate(info["feature_names"], 1):
    print(f'  {i:2d}. {feature}') 