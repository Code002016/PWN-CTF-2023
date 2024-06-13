#include <stdio.h>
#include <string.h>
int main(){

char flag_check() {
    char flag[50];
    printf("Enter The Flag: ");
    scanf("%s", flag);

    const char key1[] = {82, -55, -36, 72, -115, 57, -60, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char key2[] = {-98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 10, 22, -34, -101, -110, -62, -15, 94, -39, 40, -56, -40, -95, -10, -105, -62, -88, 48, 10, 9, -34, -111, 71, 63, -15, 70, -38, 66, -10, -55, 79, 66, -1, -43, 0, 0, 0, 0};
    const char key3[] = {-19, -70, -58, -95, -22, 72, -43, 78, -11, 39, 38, 11, -54, -33, 115, -99, -96, 61, 38, -39, -64, -8, 56, -29, -46, -10, -32, 54, -40, 11, 12, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char key4[] = {24, 90, 71, 6, 29, -29, -45, -93, 42, -27, 50, 54, -63, -78, -34, 83, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char key5[] = {-13, -27, -48, -113, 14, -83, 12, 105, 86, 99, 48, 27, -21, 8, 89, -1, -37, -17, -4, -66, 39, 6, 88, -1, -41, -77, -44, -83, 97, 57, 18, -2, -40, -55, -63, 3, -26, 42, -45, -86, 100, -109, -91, 2, -24, 96, -14, -46, -57, 0, 0, 0, 0};
    const char key6[] = {-59, -24, -15, -52, 81, -87, 59, -26, -54, -128, -36, -30, -92, -5, 9, 100, 1, -40, -4, 69, -97, 99, 20, -30, 50, -12, -25, 69, 71, 92, 6, -93, 47, 23, 34, 38, -45, -61, -9, -71, -76, -15, -17, 24, -104, -11, -128, 52, -85, -33, 0, 0, 0, 0};
    const char key7[] = {108, -45, 36, -58, -84, 113, 18, 18, 56, 3, 18, 53, 76, -75, 50, 61, -78, 56, -62, 23, 7, 96, -66, -62, -83, 21, -112, -8, 45, 45, -6, 49, -128, 22, -48, 32, 104, -93, 41, -46, -33, -87, 83, 22, -11, 52, 50, -1, -42, 0, 0, 0, 0};
    const char key8[] = {38, 11, -39, -64, -8, 56, -29, -46, -10, -32, 54, -40, 11, 12, 33, 15, -93, 39, -44, -44, -64, 84, -22, -49, 64, -53, -33, 44, -52, -29, 104, -2, 69, -97, 99, 20, -30, 50, -12, -25, 69, 71, 92, 6, -93, 47, 23, 34, 38, -45, -61, 0, 0, 0, 0};
    const char key9[] = {-37, -71, -79, -81, -3, -48, -4, -16, -45, -52, -50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char key10[] = {47, -101, -102, -19, 65, -69, 31, -61, -19, 94, -39, 40, -56, -40, -95, -10, -105, -62, -88, 48, 10, 9, -34, -111, 71, 63, -15, 70, -38, 66, -10, -55, 79, 66, -1, -43, -74, -101, -102, -95, 87, -19, 83, -1, -37, -17, -4, -66, 39, 6, 88, 0, 0, 0, 0};
    const char key11[] = {89, 22, -77, 68, -92, 20, 104, -93, 41, -46, -33, -87, 83, 22, -11, 52, 50, -1, -42, -59, 51, -2, 69, -85, -50, -33, 8, 59, 35, -15, -48, 61, 13, -22, -98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 0, 0, 0, 0};
    const char key12[] = {-10, 44, 38, -21, 49, -21, 94, 3, 62, 26, -14, -46, -57, -3, -1, -20, 40, -14, 83, 13, 100, -33, 11, -22, 96, -9, 29, 83, -68, -3, -31, 45, -61, 29, -94, -22, -48, -47, -37, -48, -50, -3, -4, -36, 40, -40, 11, -32, -128, 57, 0, 0, 0, 0};
    const char key13[] = {74, 19, -73, -128, 36, -58, -84, 113, 18, 18, 56, 3, 18, 53, 76, -75, 50, 61, -78, 56, -62, 23, 7, 96, -66, -62, -83, 21, -112, -8, 45, 45, -6, 49, -128, 22, -48, 32, 104, -93, 41, -46, -33, -87, 83, 22, -11, 52, 50, -1, -42, 0, 0, 0, 0};
    const char key14[] = {11, 4, 17, -128, 53, 43, -51, 84, -34, -12, 53, -14, -63, 4, -68, -22, 100, 33, 48, -30, 35, 18, 42, -128, 33, 62, -30, -6, 98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 10, 22, -34, -101, -110, -62, -15, 0, 0, 0, 0};
    const char key15[] = {-98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 10, 22, -34, -101, -110, -62, -15, 94, -39, 40, -56, -40, -95, -10, -105, -62, -88, 48, 10, 9, -34, -111, 71, 63, -15, 70, -38, 66, -10, -55, 79, 66, -1, -43, 0, 0, 0, 0};
    const char key16[] = {-37, -71, -79, -81, -3, -48, -4, -16, -45, -52, -50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char key17[] = {-45, -30, -71, -101, 51, 66, 53, -128, 44, 38, -21, 49, -21, 94, 3, 62, 26, -14, -46, -57, -3, -1, -20, 40, -14, 83, 13, 100, -33, 11, -22, 96, -9, 29, 83, -68, -3, -31, 45, -61, 29, -94, -22, -48, -47, -37, -48, -50, -3, -4, -36, 0, 0, 0, 0};
    const char key18[] = {-59, 51, -2, 69, -85, -50, -33, 8, 59, 35, -15, -48, 61, 13, -22, -98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 10, 22, -34, -101, -110, -62, -15, 94, -39, 40, -56, -40, -95, -10, -105, -62, -88, 48, 10, 9, 0, 0, 0, 0};
    const char key19[] = {11, 4, 17, -128, 53, 43, -51, 84, -34, -12, 53, -14, -63, 4, -68, -22, 100, 33, 48, -30, 35, 18, 42, -128, 33, 62, -30, -6, 98, -48, -41, -109, 55, -42, 41, -24, 54, 21, -87, 61, 89, -69, -87, 75, 10, 22, -34, -101, -110, -62, -15, 0, 0, 0, 0};
    const char key20[] = {47, -101, -102, -19, 65, -69, 31, -61, -19, 94, -39, 40, -56, -40, -95, -10, -105, -62, -88, 48, 10, 9, -34, -111, 71, 63, -15, 70, -38, 66, -10, -55, 79, 66, -1, -43, -74, -101, -102, -95, 87, -19, 83, -1, -37, -17, -4, -66, 39, 6, 88, 0, 0, 0, 0};

    int i;
    char result[50];
    for (i = 0; i < 49; i++) {
        char ch = flag[i];
        char ch1 = key1[(int)ch];
        char ch2 = key2[i];
        char ch3 = key3[i];
        char ch4 = key4[(int)ch3];
        char ch5 = key5[(int)ch3];
        char ch6 = key6[(int)ch5 & 1];
        char ch7 = key7[i];
        char ch8 = key8[i];
        char ch9 = key9[(int)ch8 & 3];
        char ch10 = key10[i];
        char ch11 = key11[i];
        char ch12 = key12[(int)ch11 & 3];
        char ch13 = key13[i];
        char ch14 = key14[(int)ch13];
        char ch15 = key15[(int)ch13];
        char ch16 = key16[i];
        char ch17 = key17[(int)ch16 & 7];
        char ch18 = key18[i];
        char ch19 = key19[(int)ch18 & 1];		
        char ch20 = key20[i];
        result[i] = ch1 ^ ch2 ^ ch4 ^ ch6 ^ ch7 ^ ch9 ^ ch10 ^ ch12 ^ ch14 ^ ch15 ^ ch17 ^ ch19 ^ ch20;
    }
    result[49] = '\0';

    int correct = strcmp(result, "Correct Flag");
    if (correct == 0) {
        printf("Correct Flag\n");
        return 0;
    } else {
        printf("Wrong Flag\n");
        return 1;
    }


} 
flag_check();
}
