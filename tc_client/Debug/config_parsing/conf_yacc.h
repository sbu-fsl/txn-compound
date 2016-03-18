/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_GANESHA_YY_HOME_ASHOK_WORK_FSL_FSL_NFS_GANESHA_PROXY_CLIENT_DEBUG_CONFIG_PARSING_CONF_YACC_H_INCLUDED
# define YY_GANESHA_YY_HOME_ASHOK_WORK_FSL_FSL_NFS_GANESHA_PROXY_CLIENT_DEBUG_CONFIG_PARSING_CONF_YACC_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int ganesha_yydebug;
#endif
/* "%code requires" blocks.  */
/* Line 2058 of yacc.c  */
#line 25 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/config_parsing/conf_yacc.y"

/* alert the parser that we have our own definition */
# define YYLTYPE_IS_DECLARED 1



/* Line 2058 of yacc.c  */
#line 53 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/Debug/config_parsing/conf_yacc.h"

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     _ERROR_ = 258,
     BEGIN_BLOCK = 259,
     END_BLOCK = 260,
     BEGIN_SUB_BLOCK = 261,
     END_SUB_BLOCK = 262,
     EQUAL_OP = 263,
     END_STMT = 264,
     IDENTIFIER = 265,
     KEYVALUE = 266
   };
#endif


#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2058 of yacc.c  */
#line 31 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/config_parsing/conf_yacc.y"

  char *token;
  struct config_node *node;


/* Line 2058 of yacc.c  */
#line 85 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/Debug/config_parsing/conf_yacc.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int ganesha_yyparse (void *YYPARSE_PARAM);
#else
int ganesha_yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int ganesha_yyparse (struct parser_state *st);
#else
int ganesha_yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */
/* "%code provides" blocks.  */
/* Line 2058 of yacc.c  */
#line 36 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/config_parsing/conf_yacc.y"


typedef struct YYLTYPE {
  int first_line;
  int first_column;
  int last_line;
  int last_column;
  char *filename;
} YYLTYPE;

# define YYLLOC_DEFAULT(Current, Rhs, N)			       \
    do								       \
      if (N)							       \
	{							       \
	  (Current).first_line	 = YYRHSLOC (Rhs, 1).first_line;       \
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;     \
	  (Current).last_line	 = YYRHSLOC (Rhs, N).last_line;	       \
	  (Current).last_column	 = YYRHSLOC (Rhs, N).last_column;      \
	  (Current).filename	 = YYRHSLOC (Rhs, 1).filename;	       \
	}							       \
      else							       \
	{ /* empty RHS */					       \
	  (Current).first_line	 = (Current).last_line	 =	       \
	    YYRHSLOC (Rhs, 0).last_line;			       \
	  (Current).first_column = (Current).last_column =	       \
	    YYRHSLOC (Rhs, 0).last_column;			       \
	  (Current).filename  = NULL;			     /* new */ \
	}							       \
    while (0)

int ganeshun_yylex(YYSTYPE *yylval_param,
		   YYLTYPE *yylloc_param,
		   void *scanner);

int ganesha_yylex(YYSTYPE *yylval_param,
		  YYLTYPE *yylloc_param,
		  struct parser_state *st);

void ganesha_yyerror(YYLTYPE *yylloc_param,
		     void *yyscanner,
		     char*);

struct config_node *config_block(char *blockname,
				 struct config_node *list,
				 char *filename,
				 int lineno,
				 struct parser_state *st);

void link_node(struct config_node *node);

struct config_node *config_stmt(char *varname,
				char *varval,
				char *filename,
				int lineno,
				struct parser_state *st);

#ifdef _DEBUG_PARSING
#define DEBUG_YACK   print_parse_tree
#else
#define DEBUG_YACK(...) (void)0
#endif



/* Line 2058 of yacc.c  */
#line 187 "/home/ashok/work/fsl/fsl-nfs-ganesha/proxy_client/Debug/config_parsing/conf_yacc.h"

#endif /* !YY_GANESHA_YY_HOME_ASHOK_WORK_FSL_FSL_NFS_GANESHA_PROXY_CLIENT_DEBUG_CONFIG_PARSING_CONF_YACC_H_INCLUDED  */
