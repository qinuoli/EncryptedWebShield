# -*- coding: utf-8 -*-
# 自动生成的公共参数模块 - 所有元素均为真实 Charm 对象！
from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')

# === 基础生成元 ===
g = group.deserialize('1:a6nyT8Af/+HYtIi8gYoUZIJUaLsAzydu5zGThftqyTL+uA8R/owtCpcQI78hPS2SbOC7GfekDUPJ9bMKT87T8wA='.encode('utf-8'))
gt = group.deserialize('2:l3MfkcmpDKPz0lXousCjgWBzFbIAbXK5Y0eMWWJZzACc1hFGkMScw+tzPjwDxyZNyHHr6VVfYI5sfARtc5MMjwE='.encode('utf-8'))

# === 公共参数 ===
e_alpha = group.deserialize('3:b+2w1tBwEl9wXAPB6KpobxDPiWlB5ZOw5Qwp0IbmaHZxn4/EkICiJ+KpzWDfksipQvvlbeBxavU7cDLwqwvTMk46Sq1Gp60hxWLmYPPrmLp/Vi1XT7MecKpz8T2BJkslKjZEe9+a2+1Y1ufKDDz8RMRUHWMxUVNaGDuzSq0CB60='.encode('utf-8'))
g_beta = group.deserialize('1:EJrO8bFWfv0x4T8BV8/GGXyFE48gO4OdPwaR2r2bNxH2Q7BVAu6ruxACd4TNJRN8a/eF50qEiaaRxXDXtdATbgE='.encode('utf-8'))
gt_beta = group.deserialize('2:ZvL201A/QmMAyyFjjL6B1Pj6Eg+gZMIoCn3gX/knPGkGcA4cI0eBExLULjNOwOB9IQTzZUveNkGDKF/UAWAoJQA='.encode('utf-8'))
beta_0 = 689814814894722911110035655850746326892988993300

# === 用户相关向量 ===
u = [
    group.deserialize('1:P5pDoJeIOXehnv1OejbFESHaoPyztpPoO5jNCPJX8poFmf4Kv2x/abBCwC3RlceEReD3a6K7tPePQfI51+dZBwA='.encode('utf-8')),
    group.deserialize('1:jstpxmaICmpkWJco3SKvFyW14JPifIfxWbkhUfZe/wdZjtW9ut+K7x4j1wGcRfMygn3F6kF66lVgtjUdqSHNLQA='.encode('utf-8')),
    group.deserialize('1:RKARBj/92K+0GrnWcC13ypJx9wQ9KVv9+eByBsBoE0JKNlshGqj4Qesbb1jjASTIbgdFdCk/+aNA65fvILdKhQA='.encode('utf-8')),
    group.deserialize('1:TVrJ2ItIEwlrbfsyzyf+/s1SBMMoSyGaeFW8FaWnzmkw3lDR2PGPMeLqnZzlWsp8qL1xDgK1cgyCx9+XBcFNmgE='.encode('utf-8')),
    group.deserialize('1:iYrHx5BcVyd2US7jUquzhbnkn4fn0Xj3cBiy9qFw2ooxJ08Gqm5JFtxDXWwy09+101wIF6Vh7wl8XTx775fRiQE='.encode('utf-8')),
    group.deserialize('1:hhOPuTAPL8eXQujy8c89wKhD4HUnRlMS92Liie48fcPqwE/Dk79wGYd/N3zCfwTNEE+29xwsyo5OgREoDzbV9gE='.encode('utf-8')),
]
ut = [
    group.deserialize('2:T0CFgbNcRcfdL5giIiKi5RkzqenjVYqFAAkvtXBa+k2JM3/x9EiWfNPfrryv40DBXHOYol61xAYmQTa5qfKIUAE='.encode('utf-8')),
    group.deserialize('2:McNmeMk5sA8l2XEvUAnF4Jz2winM/lR09ewtijihu3aLmhIX1F4nYAn6hgP3XERx2n9TCk6Pu5C8pGUogVGmYgA='.encode('utf-8')),
    group.deserialize('2:DdAHYQBCH3KE4dbZmVR0Ruu1xAsemCaW/Aa0a3TZUMQ9psDsS7fQK5f49+bby+C5xOf2rqLvku7k020FUTc7JwA='.encode('utf-8')),
    group.deserialize('2:ZVSyWbAEmbFXTMWn23c9NoggAzg1P9UltCKCQHuX1z9Ontk4t+icymrcwo3qwawZ4rvobe1I24tTCQi2DQpGtQE='.encode('utf-8')),
    group.deserialize('2:dnW/F2qTp5ZRqP+SgNASbx6uTf2vWdUpqqq2CQg5/36PpigaHhjcsIif802ywMYNB3wJ6wc9JqnKZ7CLaQ9QcwE='.encode('utf-8')),
    group.deserialize('2:npXOdZaEKPrFY700STkqX4QRNxO4BgxchnUCAAkV73/Mqq1Hryee11qn+XcGTkbAgYM4WHr7ovw0Dq4ZRtLeHgA='.encode('utf-8')),
]

PK = {
    'g': g, 'gt': gt,
    'e_alpha': e_alpha,
    'g_beta': g_beta,
    'gt_beta': gt_beta,
    'beta_0': beta_0,
    'u': u,
    'ut': ut,
}

print('config.py 加载成功！所有公共参数均为真实 Charm 对象')
