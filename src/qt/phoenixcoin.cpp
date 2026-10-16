/*
 * W.J. van der Laan 2011-2012
 */

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QPalette>
#include <QStyle>
#include <QStyleFactory>
#include <QSettings>
#include <QMessageBox>
#include <QLocale>
#include <QTranslator>
#include <QSplashScreen>
#include <QLibraryInfo>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>

#include "init.h"
#include "ui_interface.h"
#include "util.h"
#include "main.h"

#include "gui.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "qtipcserver.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"

#if defined(NEED_QT_PLUGINS) && !defined(_QT_PLUGINS_INCLUDED)
#define _QT_PLUGINS_INCLUDED
#define __INSURE__
#include <QtPlugin>
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
Q_IMPORT_PLUGIN(qtaccessiblewidgets)
#endif

extern CWallet *pwalletMain;

// Need a global reference for the notifications to find the GUI
static GUI *guiref;
static QSplashScreen *splashref;

static void ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    // Message from network thread
    if(guiref)
    {
        bool modal = (style & CClientUIInterface::MODAL);
        // in case of modal message, use blocking connection to wait for user to click OK
        QMetaObject::invokeMethod(guiref, "error",
                                   modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                                   Q_ARG(QString, QString::fromStdString(caption)),
                                   Q_ARG(QString, QString::fromStdString(message)),
                                   Q_ARG(bool, modal));
    }
    else
    {
        printf("%s: %s\n", caption.c_str(), message.c_str());
        fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    }
}

static bool ThreadSafeAskFee(int64 nFeeRequired, const std::string& /*strCaption*/)
{
    if(!guiref)
        return false;
    if(nFeeRequired < MIN_TX_FEE || nFeeRequired <= nTransactionFee || fDaemon)
        return true;
    bool payFee = false;

    QMetaObject::invokeMethod(guiref, "askFee", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(qint64, nFeeRequired),
                               Q_ARG(bool*, &payFee));

    return payFee;
}

static void ThreadSafeHandleURI(const std::string& strURI)
{
    if(!guiref)
        return;

    QMetaObject::invokeMethod(guiref, "handleURI", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(QString, QString::fromStdString(strURI)));
}

static void InitMessage(const std::string &message)
{
    if(splashref)
    {
        splashref->showMessage(QString::fromStdString(message), Qt::AlignBottom|Qt::AlignHCenter, QColor(255,255,200));
        QApplication::instance()->processEvents();
    }
}

static void QueueShutdown()
{
    QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
}

/*
   Translate string to current locale using Qt.
 */
static std::string Translate(const char *psz) {
    return(QCoreApplication::translate("pxc-core", psz).toStdString());
}

/* Handle runaway exceptions. Shows a message box with the problem and quits the program.
 */
static void handleRunawayException(std::exception *e) {
    PrintExceptionContinue(e, "Runaway exception");
    QMessageBox::critical(0, "Runaway exception",
      GUI::tr("A fatal error occurred. Phoenixcoin can no longer continue safely and will quit.") +
      QString("\n\n") + QString::fromStdString(strMiscWarning));
    exit(1);
}

#if !defined(Q_OS_WIN) && !defined(Q_OS_MAC)
/* The static Qt build has no fontconfig and looks for fonts in a compile-time
 * prefix directory that does not exist on other machines. Unless the caller
 * already selected a font directory, point Qt at a system font directory so the
 * binary still renders text when copied to another system. */
static void setupPortableFontDir() {
    if (qEnvironmentVariableIsSet("QT_QPA_FONTDIR"))
        return;

    const QStringList filters = {"*.ttf", "*.ttc", "*.otf", "*.pfa", "*.pfb"};
    const QStringList dirs = {
        "/usr/share/fonts/truetype/dejavu",  // Debian/Ubuntu
        "/usr/share/fonts/TTF",              // Arch/Fedora/openSUSE
        "/usr/share/fonts/truetype",
        "/usr/share/fonts",
        "/usr/local/share/fonts",
        QDir::homePath() + "/.local/share/fonts",
        QDir::homePath() + "/.fonts"
    };

    for (const QString &dir : dirs) {
        QDir d(dir);
        if (d.exists() && !d.entryList(filters, QDir::Files).isEmpty()) {
            qputenv("QT_QPA_FONTDIR", QFile::encodeName(d.absolutePath()));
            return;
        }
    }

    // Last resort: the first font file found anywhere under the usual roots
    const QStringList roots = {"/usr/share/fonts", "/usr/local/share/fonts"};
    for (const QString &root : roots) {
        QDirIterator it(root, filters, QDir::Files, QDirIterator::Subdirectories);
        if (it.hasNext()) {
            qputenv("QT_QPA_FONTDIR", QFile::encodeName(QFileInfo(it.next()).absolutePath()));
            return;
        }
    }
}
#endif

int main(int argc, char *argv[])
{
    // Do this early as we don't want to bother initializing if we are just calling IPC
    ipcScanRelay(argc, argv);

#if !defined(Q_OS_WIN) && !defined(Q_OS_MAC)
    setupPortableFontDir();
#endif

    // Internal string conversion is all UTF-8

    Q_INIT_RESOURCE(phoenixcoin);
    QApplication app(argc, argv);

    // Register the DejaVu fonts embedded in the binary's resources so text
    // renders on systems whose font directory the static (fontconfig-less) Qt
    // build cannot find. See the "/fonts" section of phoenixcoin.qrc.
    static const char *embeddedFonts[] = {
        ":/fonts/dejavu-sans",
        ":/fonts/dejavu-sans-bold",
        ":/fonts/dejavu-sans-oblique",
        ":/fonts/dejavu-sans-bold-oblique",
        ":/fonts/dejavu-sans-mono",
        ":/fonts/dejavu-sans-mono-bold"
    };
    for (const char *font : embeddedFonts)
        QFontDatabase::addApplicationFont(QString::fromLatin1(font));

    // Route the generic family names to the embedded fonts; without fontconfig
    // Qt cannot resolve "Monospace" or the generic aliases on its own.
    QFont::insertSubstitution(QStringLiteral("Monospace"), QStringLiteral("DejaVu Sans Mono"));
    QFont::insertSubstitution(QStringLiteral("Sans Serif"), QStringLiteral("DejaVu Sans"));

    // Use the embedded font as the application default so rendering is
    // identical regardless of the fonts installed on the host.
    app.setFont(QFont(QStringLiteral("DejaVu Sans"), 9));


    // Install global event filter that makes sure that long tooltips can be word-wrapped
    app.installEventFilter(new GUIUtil::ToolTipToRichTextFilter(TOOLTIP_WRAP_THRESHOLD, &app));

    // Command line options take precedence:
    ParseParameters(argc, argv);

    // ... then phoenixcoin.conf:
    if (!boost::filesystem::is_directory(GetDataDir(false)))
    {
        // This message can not be translated, as translation is not initialized yet
        // (which not yet possible because lang=XX can be overridden in phoenixcoin.conf in the data directory)
        QMessageBox::critical(0, "Phoenixcoin",
                              QString("Error: Specified data directory \"%1\" does not exist.").arg(QString::fromStdString(mapArgs["-datadir"])));
        return 1;
    }
    ReadConfigFile(mapArgs, mapMultiArgs);

    nQtStyle = GetArg("-qtstyle", 0);

    // Application identification (must be set before OptionsModel is initialized,
    // as it is used to locate QSettings)
    app.setOrganizationName("Phoenixcoin");
    app.setOrganizationDomain("phoenixcoin.org");
    if(GetBoolArg("-testnet")) // Separate UI settings for testnet
        app.setApplicationName("Phoenixcoin-Qt-testnet");
    else
        app.setApplicationName("Phoenixcoin-Qt");
    // Modern theme: Fusion style (built into static Qt) + light or dark palette.
    // Select with  -theme=light|dark  (command line or phoenixcoin.conf),
    // or with the saved -theme option from earlier runs (default: light).
    app.setStyle(QStyleFactory::create("Fusion"));

    // Read theme: -theme=light|dark, fall back to saved setting, default light
    QSettings themeSettings;
    QString strTheme = QString::fromStdString(GetArg("-theme", ""));
    if (strTheme.isEmpty())
        strTheme = themeSettings.value("strTheme", "light").toString();
    if (QString::compare(strTheme, "light", Qt::CaseInsensitive) == 0 ||
        QString::compare(strTheme, "1",    Qt::CaseInsensitive) == 0)
        strTheme = "light";
    else if (QString::compare(strTheme, "dark", Qt::CaseInsensitive) == 0)
        strTheme = "dark";
    else
        strTheme = "light";
    themeSettings.setValue("strTheme", strTheme);
    bool fDarkTheme = (QString::compare(strTheme, "dark", Qt::CaseInsensitive) == 0);

    GUIUtil::applyTheme(fDarkTheme);


    // ... then GUI settings:
    OptionsModel optionsModel;

    // Get desired locale (e.g. "de_DE") from command line or use system locale
    QString lang_territory = QString::fromStdString(GetArg("-lang", QLocale::system().name().toStdString()));
    QString lang = lang_territory;
    // Convert to "de" only by truncating "_DE"
    lang.truncate(lang_territory.lastIndexOf('_'));

    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;
    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator

    // Load e.g. qt_de.qm
    if (qtTranslatorBase.load("qt_" + lang, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        app.installTranslator(&qtTranslatorBase);

    // Load e.g. qt_de_DE.qm
    if (qtTranslator.load("qt_" + lang_territory, QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
        app.installTranslator(&qtTranslator);

    /* Load e.g. phoenixcoin_de.qm (shortcut "de" needs to be defined in phoenixcoin.qrc) */
    if (translatorBase.load(lang, ":/translations/"))
        app.installTranslator(&translatorBase);

    /* Load e.g. phoenixcoin_de_DE.qm (shortcut "de_DE" needs to be defined in phoenixcoin.qrc) */
    if (translator.load(lang_territory, ":/translations/"))
        app.installTranslator(&translator);

    // Subscribe to global signals from core
    uiInterface.ThreadSafeMessageBox.connect(ThreadSafeMessageBox);
    uiInterface.ThreadSafeAskFee.connect(ThreadSafeAskFee);
    uiInterface.ThreadSafeHandleURI.connect(ThreadSafeHandleURI);
    uiInterface.InitMessage.connect(InitMessage);
    uiInterface.QueueShutdown.connect(QueueShutdown);
    uiInterface.Translate.connect(Translate);

    // Show help message immediately after parsing command line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (mapArgs.count("-?") || mapArgs.count("--help"))
    {
        GUIUtil::HelpMessageBox help;
        help.showOrPrint();
        return 1;
    }

    QSplashScreen splash(QPixmap(":/images/splash"), Qt::WindowFlags());
    if (GetBoolArg("-splash", true) && !GetBoolArg("-min"))
    {
        splash.show();
        splash.setAutoFillBackground(true);
        splashref = &splash;
    }

    app.processEvents();

    app.setQuitOnLastWindowClosed(false);

    try
    {
        // Regenerate startup link, to fix links to old versions
        if (GUIUtil::GetStartOnSystemStartup())
            GUIUtil::SetStartOnSystemStartup(true);

        GUI window;
        guiref = &window;
        if(AppInit2())
        {
            {
                // Put this in a block, so that the Model objects are cleaned up before
                // calling Shutdown().

                optionsModel.Upgrade(); // Must be done after AppInit2

                if (splashref)
                    splash.finish(&window);

                ClientModel clientModel(&optionsModel);
                WalletModel walletModel(pwalletMain, &optionsModel);

                window.setClientModel(&clientModel);
                window.setWalletModel(&walletModel);

                // If -min option passed, start window minimized.
                if(GetBoolArg("-min"))
                {
                    window.showMinimized();
                }
                else
                {
                    window.show();
                }

                // Place this here as guiref has to be defined if we don't want to lose URIs
                ipcInit(argc, argv);

                app.exec();

                window.hide();
                window.setClientModel(0);
                window.setWalletModel(0);
                guiref = 0;
            }
            /* Shutdown the core and its threads, but don't exit Phoenixcoin-Qt here */
            Shutdown(NULL);
        }
        else
        {
            return 1;
        }
    } catch (std::exception& e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(NULL);
    }
    return 0;
}
