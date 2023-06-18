//
// Created by Xuefeng Huang on 2020/1/28.
//

#ifndef TEXASSOLVER_CARD_H
#define TEXASSOLVER_CARD_H
#include <iostream>
#include <string>
#include <vector>
#include "tinyformat.h"


using namespace std;

/*
1.card有三种表示形式，字符串，int，和long
字符串有两个属性,rank为牌的大小，2到A，suit为牌的花色，牌的花色顺序为cdhs，梅花，方块，红桃，黑桃
2.int为花色乘以4加rank的牌值
3.Long为牌的按int值对64位long置位
4.所有成员函数中的boardCard指的时card，函数参数传入card,boardCards指的是多张牌
5，函数返回单张牌一般用int，多张牌一般card
*/
class Card {
    private:
        string card;//牌的字符串形式
        int card_int;//52张牌的编号0-51
        //该值的意义待确定,该值为牌的int值，即0-51(0-36)的编号，
        //为rank*4+suit与card_int的值相同,在短牌是与card_int不同，取值为0-36
        int card_number_in_deck; 
    public:
        Card();
        explicit Card(string card,int card_number_in_deck);
        Card(string card);
        string getCard();
        int getCardInt();
        bool empty();
        int getNumberInDeckInt();
        static int card2int(Card card);
        static int strCard2int(string card);
        static string intCard2Str(int card);
        static uint64_t boardCards2long(vector<string> cards);
        static uint64_t boardCard2long(Card& card);
        static uint64_t boardCards2long(vector<Card>& cards);
        static inline bool boardsHasIntercept(uint64_t board1,uint64_t board2){
            return ((board1 & board2) != 0);
        };
        static uint64_t boardInts2long(const vector<int>& board);
        static uint64_t boardInt2long(int board);
        static vector<int> long2board(uint64_t board_long);
        static vector<Card> long2boardCards(uint64_t board_long);
        static string suitToString(int suit);
        static string rankToString(int rank);
        static int rankToInt(char rank);
        static int suitToInt(char suit);
        static vector<string> getSuits();
        string toString();
};

#endif //TEXASSOLVER_CARD_H
