#ifndef _FIXED_POINT_H_
#define _FIXED_POINT_H_

#define _p_ (17)
#define _q_ (14)
#define _f_ (1 << (_q_))


#define int_to_fp(n)    ((n) * (_f_))
#define fp_to_int(x)    ((x) / (_f_))
#define fp_to_int_round(x)  (x >= 0 ? ((x + _f_ / 2) / _f_) : ((x - _f_ / 2) / _f_))
#define add_fp(x, y)    (x + y)
#define sub_fp(x, y)    (x - y)
#define add_fp_int(x, n)    (x + n * _f_)

#define sub_fp_int(x, n)    (x - n * _f_)
#define mul_fp(x, y)    ((((int64_t)x) * y / _f_))
#define mul_fp_int(x, n)    (x * n)
#define div_fp(x, y)    ((((int64_t)x) * _f_ / y))
#define div_fp_int(x, n)    (x / n)

#endif
