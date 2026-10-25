use re0auth_api::ports::Storage;

pub async fn device_attempt_contract<S: Storage>(store: &S) {
    let ip = "127.0.0.1";
    let hash = vec![0x71_u8; 32];
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 1000)
            .await
            .unwrap(),
        0
    );
    for at in 1000..1005 {
        store
            .device_attempts()
            .record_miss(ip, &hash, at)
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 1004)
            .await
            .unwrap(),
        5
    );
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 1903)
            .await
            .unwrap(),
        5
    );
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 1904)
            .await
            .unwrap(),
        0
    );

    store.device_attempts().clear(ip, &hash).await.unwrap();
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 1004)
            .await
            .unwrap(),
        0
    );

    assert_eq!(
        store
            .device_attempts()
            .record_miss(ip, &hash, 2000)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.device_attempts().purge_expired(2900).await.unwrap(),
        1
    );
    assert_eq!(
        store
            .device_attempts()
            .misses(ip, &hash, 2000)
            .await
            .unwrap(),
        0
    );
}
