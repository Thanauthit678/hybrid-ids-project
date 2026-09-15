"""
utils.py
=========
ฟังก์ชันช่วยเหลือที่ใช้ร่วมกันใน 04_loao_evaluation.py และ 05_train_final_model.py
"""
from collections import Counter
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split


def safe_train_test_split(X, y, test_size=0.2, random_state=42, **kwargs):
    """
    เหมือน sklearn.train_test_split(..., stratify=y) ทุกอย่าง แต่กันปัญหาคลาสที่มี
    ตัวอย่างน้อยเกินไป (เช่น Heartbleed ใน CICIDS2017 มีแค่ ~11 samples) ซึ่งอาจทำให้
    stratify=y โยน ValueError ถ้าคลาสใดเหลือตัวอย่างในผลลัพธ์น้อยกว่า 2
    ถ้า stratify ทำไม่ได้ จะ fallback ไปแบ่งแบบสุ่มทั่วไปแทน (พร้อม print เตือน)
    """
    counts = y.value_counts()
    too_small = counts[counts < 2]
    if len(too_small) > 0:
        print(f"   [WARNING] พบคลาสตัวอย่างน้อยกว่า 2: {too_small.to_dict()} "
              f"-> แบ่งข้อมูลแบบไม่ stratify แทน")
        return train_test_split(X, y, test_size=test_size, random_state=random_state, **kwargs)

    try:
        return train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y, **kwargs
        )
    except ValueError as e:
        print(f"   [WARNING] stratify ล้มเหลว ({e}) -> แบ่งข้อมูลแบบไม่ stratify แทน")
        return train_test_split(X, y, test_size=test_size, random_state=random_state, **kwargs)


def apply_balanced_smote(X, y, cap_ratio=0.3, min_target=3000, random_state=42, verbose=True):
    """
    ใช้ SMOTE oversample เฉพาะคลาสที่มีจำนวนน้อยกว่า target แบบจำกัดเพดาน
    (ไม่ oversample จนเท่า majority class เพราะ CICIDS2017 มี BENIGN เยอะมาก
     ถ้า oversample ให้เท่ากันหมดจะทำให้ข้อมูลใหญ่เกินจำเป็นและใช้เวลานานมาก)

    target = max(min_target, จำนวน majority class * cap_ratio)
    คลาสที่มีตัวอย่างน้อยกว่า 2 รายการจะถูกข้าม (SMOTE สร้าง synthetic sample ไม่ได้
    ถ้าไม่มีเพื่อนบ้านให้ interpolate)

    คืนค่า: (X_resampled, y_resampled)
    """
    counts = Counter(y)
    majority = max(counts.values())
    target = max(min_target, int(majority * cap_ratio))

    strategy = {cls: target for cls, cnt in counts.items() if 2 <= cnt < target}
    skipped = [cls for cls, cnt in counts.items() if cnt < 2]

    if skipped and verbose:
        print(f"   [SMOTE] ข้ามคลาส {skipped} เพราะมีตัวอย่างน้อยกว่า 2 (สร้าง synthetic sample ไม่ได้)")

    if not strategy:
        if verbose:
            print("   [SMOTE] ไม่มีคลาสที่ต้อง oversample เพิ่มเติม ข้ามขั้นตอนนี้")
        return X, y

    # k_neighbors ต้องไม่เกินจำนวนตัวอย่าง-1 ของคลาสที่เล็กที่สุดในกลุ่มที่จะ oversample
    min_count_in_strategy = min(counts[c] for c in strategy)
    k_neighbors = max(1, min(5, min_count_in_strategy - 1))

    if verbose:
        print(f"   [SMOTE] oversample {len(strategy)} คลาส -> เป้าหมาย {target:,} ตัวอย่าง/คลาส "
              f"(k_neighbors={k_neighbors})")

    smote = SMOTE(sampling_strategy=strategy, k_neighbors=k_neighbors, random_state=random_state)
    X_res, y_res = smote.fit_resample(X, y)

    if verbose:
        print(f"   [SMOTE] ขนาดข้อมูลก่อน: {len(y):,} -> หลัง: {len(y_res):,}")

    return X_res, y_res
