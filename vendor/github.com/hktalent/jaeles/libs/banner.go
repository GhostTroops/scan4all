package libs

import (
	"github.com/fatih/color"
)

// Banner print ascii banner
func Banner() string {
	version := color.HiWhiteString(VERSION)
	author := color.MagentaString(AUTHOR)
	b := color.GreenString(``)

	b += "\n" + color.HiGreenString(``)
	b += "\n" + color.GreenString(`                                           ,+izzir,                                   `)
	b += "\n" + color.GreenString(`                                        '*K@@Q8&Q@@8t'                                `)
	b += "\n" + color.GreenString(`                                       !Q@N;''`) + color.HiWhiteString(`,~~;`) + color.GreenString(`\D@@t'                              `)
	b += "\n" + color.GreenString(`                                      ,Q@q. `) + color.HiWhiteString(`'~~~~~~;`) + color.GreenString(`5@@L                              `)
	b += "\n" + color.GreenString(`                                      L@@+  `) + color.HiWhiteString(`'~~~~~~~`) + color.GreenString(`^Q@X                              `)
	b += "\n" + color.GreenString(`                                      ^@@z  `) + color.HiWhiteString(`'~~~~~~~`) + color.GreenString(`|Q@y                              `)
	b += "\n" + color.GreenString(`                                      'Z@@7  `) + color.HiWhiteString(`'~~~~;`) + color.GreenString(`TQ@N,                              `)
	b += "\n" + color.GreenString(`                                        ^%@QhJ7fmDQ@Q7'     ~}DQ@@@Qqv,               `)
	b += "\n" + color.GreenString(`                                          ~jdQ@@Qdjr'     ,U@@qv=|tm#@QY              `)
	b += "\n" + color.GreenString(`                                             *@@=         D@&;`) + color.HiWhiteString(`  ,~~~`) + color.GreenString(`;f@@^             `)
	b += "\n" + color.GreenString(`                                             <@@+        .@@L`) + color.HiWhiteString(`  '~~~~~~`) + color.GreenString(`K@P             `)
	b += "\n" + color.GreenString(`                                          ,<zb@@K7<~'    'Q@f`) + color.HiWhiteString(`  '_~~~~`) + color.GreenString(`!N@j             `)
	b += "\n" + color.GreenString(`                                       !XQ@QA5jEbWQ@@Ri.'*Q@@D`) + color.HiWhiteString(`+'',;=j`) + color.GreenString(`Q@#.             `)
	b += "\n" + color.GreenString(`                                     _d@@a!`) + color.HiBlueString(`  ';^rr=7`) + color.GreenString(`kQ@QQ@RzoQ@@Q#Q@@Nz.              `)
	b += "\n" + color.GreenString(`                                    ;Q@D_`) + color.HiBlueString(`  '~^^r^^rr^`) + color.GreenString(`|K@@K   ';*\vi=_'                `)
	b += "\n" + color.GreenString(`                                   '8@%'`) + color.HiBlueString(`   ~^^r^r^^^r^`) + color.GreenString(`=A@@'                           `)
	b += "\n" + color.GreenString(`          ,<}kKKhI='               =@@*`) + color.HiBlueString(`  ^qfr^rrrrj8U<`) + color.GreenString(`^iQ@*                           `)
	b += "\n" + color.GreenString(`        !b@@NXaURQ@@U;         ''~+P@@L`) + color.HiBlueString(`  z@Qv^^^rrz6y=`) + color.GreenString(`r7@@=                           `)
	b += "\n" + color.GreenString(`      'y@@a~`) + color.HiWhiteString(` ',~~;`) + color.GreenString(`LD@@7  '^^' \Q@@@Q@@W'`) + color.HiBlueString(` 'y@@RXXDdT^^r=`) + color.GreenString(`b@@'                           `)
	b += "\n" + color.GreenString(`      T@@i`) + color.HiWhiteString(`  ',~~~~~;`) + color.GreenString(`E@@= ,D%~ '<^~''~Q@%~`) + color.HiBlueString(`  =ENQQNKi^r`) + color.GreenString(`LD@@7                            `)
	b += "\n" + color.GreenString(`      X@#'`) + color.HiWhiteString(`  '~~~~~~~`) + color.GreenString(`<Q@o             ,6@@X+'`) + color.HiBlueString(` ,!+^+<J`) + color.GreenString(`6Q@&+                             `)
	b += "\n" + color.GreenString(`      n@@^`) + color.HiWhiteString(`   ,~~~~~~`) + color.GreenString(`f@@i               '7R@@QgDWQQ@@@Q<                               `)
	b += "\n" + color.GreenString(`      'b@Qi'`) + color.HiWhiteString(` ',~~~`) + color.GreenString(`^S@@m'                  '^iYjjxi^=Q@%,                              `)
	b += "\n" + color.GreenString(`       '7Q@QEzLYmDQ@BL'                             :8@#~                             `)
	b += "\n" + color.GreenString(`         '+yb#QQNKf^'                                ,R@Q; '''                        `)
	b += "\n" + color.GreenString(`                                                      'b@@#Q@@QDj^'                   `)
	b += "\n" + color.GreenString(`                                                     ,X@@K`) + color.HiWhiteString(`?!=|7m`) + color.GreenString(`Q@Q}'                 `)
	b += "\n" + color.GreenString(`                                                    ,N@W;`) + color.HiWhiteString(` '~~~~~;`) + color.GreenString(`IQ@q'                `)
	b += "\n" + color.GreenString(`                                                    }@Q~`) + color.HiWhiteString(`  ,~~~~~~~`) + color.GreenString(`f@@=                `)
	b += "\n" + color.GreenString(`                                                    E@Q'`) + color.HiWhiteString(`  ~~~~~~~~`) + color.GreenString(`7@@L                `)
	b += "\n" + color.GreenString(`                                                    +@@}'`) + color.HiWhiteString(` ,~~~~~~^`) + color.GreenString(`%@Q_                `)
	b += "\n" + color.GreenString(`                                                     ^Q@Qz,`) + color.HiWhiteString(`,~;^\UQ`) + color.GreenString(`@D_                 `)
	b += "\n" + color.GreenString(`                                                      .iD@@QQQ@@QU='                  `)
	b += "\n" + color.GreenString(`                                                         '^|iL>~'   `)

	b += "\n\n" + color.GreenString(`	`)

	b += "\n" + color.CyanString(`         		 🚀 Jaeles %v`, version) + color.CyanString(` by %v 🚀`, author)
	b += "\n\n" + color.HiWhiteString(`               The Swiss Army knife for automated Web Application Testing  `)
	b += "\n\n" + color.HiGreenString(`                                     ¯\_(ツ)_/¯`) + "\n\n"
	color.Unset()
	return b
}
