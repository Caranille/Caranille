<?php
require_once("../../kernel/kernel.php");
require_once("../../kernel/security/passwordManager.php");
require_once("../../html/header.php");

//Si les variables $_POST suivantes existent
if (isset($_POST['accountPseudo']) 
&& isset($_POST['accountPassword'])
&& isset($_POST['accountPasswordConfirm'])
&& isset($_POST['accountEmail'])
&& isset($_POST['accountEmailConfirm'])
&& isset($_POST['characterclasseId'])
&& isset($_POST['characterSex'])
&& isset($_POST['characterName'])
&& isset($_POST['token'])
&& isset($_POST['register']))
{
    //Si le token de sécurité est correct
    if ($_POST['token'] == $_SESSION['token'])
    {
        //On supprime le token de l'ancien formulaire
        $_SESSION['token'] = NULL;
        
        //On vérifie si tous les champs numérique contiennent bien un nombre entier positif
        if (ctype_digit($_POST['characterclasseId'])
        && ctype_digit($_POST['characterSex'])
        && $_POST['characterclasseId'] >= 1
        && $_POST['characterSex'] >= 0
        && $_POST['characterSex'] <= 1)
        {
            //On récupère les valeurs du formulaire dans une variable
            $accountPseudo = htmlspecialchars($_POST['accountPseudo']);
            $accountPassword = $_POST['accountPassword'];
            $accountPasswordConfirm = $_POST['accountPasswordConfirm'];
            $accountEmail = htmlspecialchars($_POST['accountEmail']);
            $accountEmailConfirm = htmlspecialchars($_POST['accountEmailConfirm']);
            $characterclasseId = htmlspecialchars($_POST['characterclasseId']);
            $characterSex = htmlspecialchars($_POST['characterSex']);
            $characterName = htmlspecialchars($_POST['characterName']);
    
            //On vérifie si les deux mots de passes sont identiques (avant hash)
            if ($accountPassword == $accountPasswordConfirm) 
            {
                //On vérifie si les deux adresses emails sont identique
                if ($accountEmail == $accountEmailConfirm) 
                {
                    //On fait une requête pour vérifier si le pseudo est déjà utilisé
                    $pseudoQuery = $bdd->prepare("SELECT * FROM car_accounts 
                    WHERE accountPseudo= ?");
                    $pseudoQuery->execute([$accountPseudo]);
                    $pseudoRow = $pseudoQuery->rowCount();
                    $pseudoQuery->closeCursor();
        
                    //Si le pseudo est disponible
                    if ($pseudoRow == 0) 
                    {
                        //On fait une requête pour vérifier si l'adresse email est déjà utilisé
                        $emailQuery = $bdd->prepare("SELECT * FROM car_accounts 
                        WHERE accountEmail= ?");
                        $emailQuery->execute([$accountEmail]);
                        $emailRow = $emailQuery->rowCount();
                        $emailQuery->closeCursor();

                        //Si l'adresse email est disponible
                        if ($emailRow == 0) 
                        {
                            //On fait une requête pour vérifier si le nom du personnage est déjà utilisé
                            $characterQuery = $bdd->prepare("SELECT * FROM car_characters 
                            WHERE characterName= ?");
                            $characterQuery->execute([$characterName]);
                            $characterRow = $characterQuery->rowCount();
                            $characterQuery->closeCursor();
            
                            //Si le personnage existe
                            if ($characterRow == 0) 
                            {
                                //On fait une requête pour vérifier si le nom du personnage est déjà utilisé
                                $classeQuery = $bdd->prepare("SELECT * FROM car_classes 
                                WHERE classeId = ?");
                                $classeQuery->execute([$characterclasseId]);
                                $classeRow = $classeQuery->rowCount();
                                $classeQuery->closeCursor();
            
                                //Si la classe du personnage existe
                                if ($classeRow >= 1) 
                                {
                                    //On hash le mot de passe soumis
                                    $accountPasswordHash = PasswordManager::hashPassword($accountPassword);
                                    
                                    //Variables pour la création d'un compte
                                    $date = date('Y-m-d H:i:s');
                                    $ip = $_SERVER['REMOTE_ADDR'];
                                    $timeStamp = strtotime("now");
            
                                    //Insertion du compte dans la base de donnée
                                    $addAccount = $bdd->prepare("INSERT INTO car_accounts VALUES(
                                    NULL,
                                    :accountPseudo,
                                    :accountPassword,
                                    :accountEmail,
                                    '',
                                    '',
                                    '0',
                                    '0',
                                    'None',
                                    :accountLastAction,
                                    :accountLastConnection,
                                    :accountIp)");
                                    $addAccount->execute([
                                    'accountPseudo' => $accountPseudo,
                                    'accountPassword' => $accountPasswordHash,
                                    'accountEmail' => $accountEmail,
                                    'accountLastAction' => $date,
                                    'accountLastConnection' => $date,
                                    'accountIp' => $ip]);
                                    $addAccount->closeCursor();
            
                                    //On recherche l'id du personnage
                                    $accountQuery = $bdd->prepare("SELECT * FROM car_accounts 
                                    WHERE accountPseudo = ?");
                                    $accountQuery->execute([$accountPseudo]);
            
                                    while ($account = $accountQuery->fetch())
                                    {
                                        //On Stock l'id du compte
                                        $accountId = $account['accountId'];
                                    }
                                    $accountQuery->closeCursor();
            
                                    $addCharacter = $bdd->prepare("INSERT INTO car_characters VALUES(
                                    NULL,
                                    :accountId,
                                    '0',
                                    :characterclasseId,
                                    '0',
                                    '../../img/empty.png',
                                    :characterName,
                                    '1',
                                    :characterSex,
                                    '100',
                                    '100',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '100',
                                    '10',
                                    '10',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '10',
                                    '1',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '1',
                                    '1',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '1',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '0',
                                    '1',
                                    '0',
                                    '1'
                                    )");
                                    $addCharacter->execute([
                                    'accountId' => $accountId,
                                    'characterclasseId' => $characterclasseId,
                                    'characterName' => $characterName,
                                    'characterSex' => $characterSex]);
                                    $addCharacter->closeCursor();
                                    ?>

                                    Compte crée

                                    <hr>

                                    <form method="POST" action="../../index.php">
                                        <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Continuer">
                                    </form>
                                        
                                    <?php
                                }
                                //Si la classe choisie n'existe pas
                                else
                                {
                                    echo "La classe choisit n'existe pas";
                                }
                                $classeQuery->closeCursor();  
                            }
                            //Si le nom du personnage a déjà été utilisé
                            else
                            {
                                ?>

                                Ce nom de personnage est déjà utilisé

                                <hr>

                                <form method="POST" action="../../modules/register/index.php">
                                    <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Recommencer">
                                </form>

                                <?php
                            }
                            $characterQuery->closeCursor();
                        }
                        else
                        {
                            ?>

                            L'adresse email est déjà utilisée

                            <hr>

                            <form method="POST" action="../../modules/register/index.php">
                                <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Recommencer">
                            </form>

                            <?php
                        }
                    }
                    //Si le pseudo est déjà utilisé
                    else 
                    {
                        ?>

                        Le pseudo est déjà utilisé

                        <hr>

                        <form method="POST" action="../../modules/register/index.php">
                            <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Recommencer">
                        </form>

                        <?php
                    }
                    $pseudoQuery->closeCursor();   
                }
                else
                {
                    ?>

                    Les deux adresses emails entrée ne sont pas identique

                    <hr>

                    <form method="POST" action="../../modules/register/index.php">
                        <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Recommencer">
                    </form>

                    <?php
                }
            }
            //Si les deux mots de passe ne sont pas identique
            else 
            {
                ?>

                Les deux mots de passe entrée ne sont pas identique

                <hr>

                <form method="POST" action="../../modules/register/index.php">
                    <input type="submit" name="continue" class="btn btn-secondary btn-lg" value="Recommencer">
                </form>

                <?php
            }
        }
        //Si tous les champs numérique ne contiennent pas un nombre
        else
        {
            echo "Erreur : Les champs de type numérique ne peuvent contenir qu'un nombre entier";
        }
    }
    //Si le token de sécurité n'est pas correct
    else
    {
        echo "Erreur : La session a expirée, veuillez réessayer";
    }
}
//Si toutes les variables $_POST n'existent pas
else 
{
    echo "Tous les champs n'ont pas été rempli";
}

require_once("../../html/footer.php"); ?>
