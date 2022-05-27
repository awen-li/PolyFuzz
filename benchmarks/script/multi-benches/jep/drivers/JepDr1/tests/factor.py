def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n - 1)


n = 4
print(factorial(n))
